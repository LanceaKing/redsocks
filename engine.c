#include "engine.h"
#include "engine-internal.h"
#include "cntlm-embed.h"
#include "main.h"
#include "log.h"
#include "base.h"
#include <event2/event.h>
#include <openssl/opensslv.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>

extern app_subsys base_subsys, redsocks_subsys, redudp_subsys, dnstc_subsys, dnsu2t_subsys;
static app_subsys *subsystems[] = { &base_subsys, &redsocks_subsys,
    &redudp_subsys, &dnstc_subsys, &dnsu2t_subsys };
struct redsocks_engine {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    pthread_t thread;
    int joinable, state, result, validate;
    int wake[2];
    redsocks_engine_options options;
    struct event_base *base;
    char diagnostic[512];
    const char *detect_url;
    char *detect_output;
    size_t detect_capacity;
};
/* Legacy subsystem registries are process-global. The gate covers parsing,
 * running, cleanup and validation, including every cntlm session/cache. */
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static redsocks_engine *active;
static redsocks_engine *owner;
struct event_base *redsocks_event_base(void) { return active ? active->base : NULL; }
int redsocks_trust_fd(void) { return active ? active->options.trust_fd : -1; }
void redsocks_engine_error(const char *message) {
    if (!active) return;
    pthread_mutex_lock(&active->mutex);
    snprintf(active->diagnostic, sizeof(active->diagnostic), "%s", message);
    pthread_mutex_unlock(&active->mutex);
}
int redsocks_apply_socket_mark(int fd) {
    uint32_t mark = active ? active->options.socket_mark : 0;
    if (!mark) return 0;
#ifdef SO_MARK
    if (!setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) return 0;
#else
    errno = ENOTSUP;
#endif
    redsocks_engine_error("Unable to mark outbound socket");
    return -1;
}
static void set_state(redsocks_engine *e, int state) {
    pthread_mutex_lock(&e->mutex);
    e->state = state;
    pthread_cond_broadcast(&e->changed);
    pthread_mutex_unlock(&e->mutex);
}
static void stop_event(int fd, short events, void *arg) {
    redsocks_engine *e = arg;
    char bytes[32];
    (void)events;
    while (read(fd, bytes, sizeof(bytes)) > 0) {}
    set_state(e, REDSOCKS_STOPPING);
    cntlm_embed_stop();
    event_base_loopbreak(e->base);
}
static void close_options(redsocks_engine *e) {
    if (e->options.config_fd >= 0) close(e->options.config_fd);
    if (e->options.trust_fd >= 0) close(e->options.trust_fd);
    if (e->options.cntlm_fd >= 0) close(e->options.cntlm_fd);
    e->options.config_fd = e->options.trust_fd = e->options.cntlm_fd = -1;
}
static void *engine_thread(void *arg) {
    redsocks_engine *e = arg;
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &blocked, NULL); /* this thread and its children only */
    active = e;
    e->result = -1;
    struct event *wake = NULL;
    e->base = event_base_new();
    if (!e->base) goto cleanup;
    FILE *file = fdopen(dup(e->options.config_fd), "r");
    if (!file) goto cleanup;
    rewind(file);
    parser_context *parser = parser_start(file);
    if (!parser) { fclose(file); goto cleanup; }
    for (size_t i = 0; i < SIZEOF_ARRAY(subsystems); ++i)
        parser_add_section(parser, subsystems[i]->conf_section);
    int parsed = parser_run(parser);
    parser_stop(parser);
    fclose(file);
    if (parsed) { redsocks_engine_error("Invalid redsocks configuration"); goto cleanup; }
    if (cntlm_embed_init(e->options.cntlm_fd, e->base, !e->validate)) goto cleanup;
    extern int redsocks_prepare_transports(void);
    if (redsocks_prepare_transports()) goto cleanup;
    if (e->detect_url) {
        e->result = cntlm_embed_detect(e->detect_url, e->detect_output, e->detect_capacity);
        goto cleanup;
    }
    if (e->validate) { e->result = 0; goto cleanup; }
    for (size_t i = 0; i < SIZEOF_ARRAY(subsystems); ++i) {
        if (subsystems[i]->init(e->base)) {
            redsocks_engine_error("Native subsystem initialization failed");
            goto cleanup;
        }
    }
    wake = event_new(e->base, e->wake[0], EV_READ | EV_PERSIST, stop_event, e);
    if (!wake || event_add(wake, NULL)) goto cleanup;
    log_error(LOG_NOTICE, "redsocks started, conn_max=%u", redsocks_conn_max());
    set_state(e, REDSOCKS_RUNNING);
    e->result = event_base_dispatch(e->base) < 0 ? -1 : 0;
    log_error(LOG_NOTICE, "redsocks goes down");
cleanup:
    cntlm_embed_stop();
    cntlm_embed_fini();
    for (size_t i = SIZEOF_ARRAY(subsystems); i > 0; --i) {
        app_subsys *s = subsystems[i-1];
        if (s->fini) s->fini();
        if (s->conf_section) {
            s->conf_section->data = NULL;
            s->conf_section->next = NULL;
            s->conf_section->context = NULL;
        }
    }
    if (wake) event_free(wake);
    if (e->base) event_base_free(e->base);
    e->base = NULL;
    redsocks_log_reset();
    close_options(e);
    set_state(e, e->result ? REDSOCKS_FAILED : REDSOCKS_STOPPED);
    active = NULL;
    pthread_mutex_lock(&gate);
    owner = NULL;
    pthread_mutex_unlock(&gate);
    return NULL;
}
redsocks_engine *redsocks_engine_create(void) {
    redsocks_engine *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    pthread_mutex_init(&e->mutex, NULL);
    pthread_cond_init(&e->changed, NULL);
    e->wake[0] = e->wake[1] = -1;
    e->options.config_fd = e->options.trust_fd = e->options.cntlm_fd = -1;
    return e;
}
static int start(redsocks_engine *e, const redsocks_engine_options *o, int validate) {
    if (!e || !o || o->config_fd < 0) return -1;
    int state = redsocks_engine_get_status(e);
    if (state == REDSOCKS_RUNNING || state == REDSOCKS_STARTING || state == REDSOCKS_STOPPING) return -1;
    redsocks_engine_join(e);
    pthread_mutex_lock(&gate);
    if (owner) {
        pthread_mutex_unlock(&gate);
        pthread_mutex_lock(&e->mutex);
        snprintf(e->diagnostic, sizeof(e->diagnostic), "Another native engine is active");
        pthread_mutex_unlock(&e->mutex);
        return -1;
    }
    owner = e;
    pthread_mutex_unlock(&gate);
    e->options = *o;
    e->options.config_fd = dup(o->config_fd);
    e->options.trust_fd = o->trust_fd >= 0 ? dup(o->trust_fd) : -1;
    e->options.cntlm_fd = o->cntlm_fd >= 0 ? dup(o->cntlm_fd) : -1;
    e->validate = validate;
    e->diagnostic[0] = 0;
    if (e->options.config_fd < 0 || (o->trust_fd >= 0 && e->options.trust_fd < 0) ||
        (o->cntlm_fd >= 0 && e->options.cntlm_fd < 0) ||
        socketpair(AF_UNIX, SOCK_STREAM, 0, e->wake)) goto fail;
    for (int i = 0; i < 2; ++i) {
        fcntl(e->wake[i], F_SETFL, fcntl(e->wake[i], F_GETFL) | O_NONBLOCK);
        fcntl(e->wake[i], F_SETFD, FD_CLOEXEC);
    }
    set_state(e, REDSOCKS_STARTING);
    if (pthread_create(&e->thread, NULL, engine_thread, e)) goto fail;
    e->joinable = 1;
    pthread_mutex_lock(&e->mutex);
    while (e->state == REDSOCKS_STARTING) pthread_cond_wait(&e->changed, &e->mutex);
    int ok = validate ? e->state == REDSOCKS_STOPPED : e->state == REDSOCKS_RUNNING;
    pthread_mutex_unlock(&e->mutex);
    if (!ok || validate) redsocks_engine_join(e);
    return ok ? 0 : -1;
fail:
    close_options(e);
    for (int i = 0; i < 2; ++i) if (e->wake[i] >= 0) { close(e->wake[i]); e->wake[i] = -1; }
    set_state(e, REDSOCKS_FAILED);
    pthread_mutex_lock(&gate); owner = NULL; pthread_mutex_unlock(&gate);
    return -1;
}
int redsocks_engine_start(redsocks_engine *e, const redsocks_engine_options *o) { return start(e, o, 0); }
int redsocks_engine_validate(redsocks_engine *e, const redsocks_engine_options *o) { return start(e, o, 1); }
void redsocks_engine_request_stop(redsocks_engine *e) {
    if (!e) return;
    pthread_mutex_lock(&e->mutex);
    if (e->wake[1] >= 0) send(e->wake[1], "s", 1, MSG_NOSIGNAL);
    pthread_mutex_unlock(&e->mutex);
}
int redsocks_engine_join(redsocks_engine *e) {
    if (!e) return -1;
    if (e->joinable) { pthread_join(e->thread, NULL); e->joinable = 0; }
    pthread_mutex_lock(&e->mutex);
    for (int i = 0; i < 2; ++i) if (e->wake[i] >= 0) { close(e->wake[i]); e->wake[i] = -1; }
    pthread_mutex_unlock(&e->mutex);
    return e->result;
}
void redsocks_engine_destroy(redsocks_engine *e) {
    if (!e) return;
    redsocks_engine_request_stop(e);
    redsocks_engine_join(e);
    pthread_mutex_destroy(&e->mutex);
    pthread_cond_destroy(&e->changed);
    memset(e, 0, sizeof(*e));
    free(e);
}
int redsocks_engine_get_status(redsocks_engine *e) {
    if (!e) return REDSOCKS_STOPPED;
    pthread_mutex_lock(&e->mutex);
    int state = e->state;
    pthread_mutex_unlock(&e->mutex);
    return state;
}
size_t redsocks_engine_diagnostics(redsocks_engine *e, char *out, size_t len) {
    if (!e || !out || !len) return 0;
    pthread_mutex_lock(&e->mutex);
    size_t result = snprintf(out, len, "%s", e->diagnostic);
    pthread_mutex_unlock(&e->mutex);
    return result;
}
int redsocks_engine_hashes(const char *u, const char *d, const char *p, char *o, size_t n) {
    return cntlm_embed_hashes(u, d, p, o, n);
}
int redsocks_engine_detect(redsocks_engine *e, const redsocks_engine_options *o,
    const char *url, char *out, size_t len) {
    if (!e || !url || !out || !len) return -1;
    e->detect_url = url; e->detect_output = out; e->detect_capacity = len;
    int result = start(e, o, 1);
    e->detect_url = NULL; e->detect_output = NULL;
    return result;
}
const char *redsocks_engine_build_info(void) {
    return "redsocks shared engine; cntlm " REDSOCKS_CNTLM_VERSION "; " OPENSSL_VERSION_TEXT "; libevent " LIBEVENT_VERSION;
}
