/* Embedded orchestration of the complete upstream cntlm protocol modules.
 * cntlm is GPL-2.0-or-later; see ../cntlm/COPYRIGHT and LICENSE. */
#include <event2/event.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <setjmp.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include "cntlm-io.h"
#include "cntlm-embed.h"
#include "engine-internal.h"
#include "globals.h"
#include "config.h"
#include "ntlm.h"
#include "acl.h"
#include "socket.h"
#include "http.h"
#include "forward.h"
#include "proxy.h"
#include "pac.h"
#include "swap.h"

extern plist_t noproxy_add(plist_t, char *);
extern void *proxy_thread(void *);
extern void *tunnel_thread(void *);
extern void *socks5_thread(void *);

typedef struct worker {
    struct worker *next;
    pthread_t thread;
    int fd, mode, done;
    union sock_addr peer;
    char *target;
    void *prefix;
    size_t prefix_len;
} worker;
typedef struct listener {
    struct listener *next;
    struct event *event;
    int fd, mode;
    char *target;
} listener;
static worker *workers;
static listener *listeners;
static struct event *reaper;
static plist_t rules;
static int enabled, stopped;
static __thread jmp_buf *failure_target;
static struct auth_s *new_auth(void) {
    struct auth_s *creds = calloc(1, sizeof(*creds));
    if (creds) creds->hashntlm2 = 1;
    return creds;
}
uint64_t cntlm_embed_random(void) {
    uint64_t value;
    if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) cntlm_embed_fatal();
    return value;
}

void cntlm_embed_fatal(void) {
    redsocks_engine_error("cntlm allocation or configuration failure");
    if (failure_target) longjmp(*failure_target, 1);
    pthread_exit(NULL); /* never exit/abort the JVM host */
}
void cntlm_embed_log(int priority, const char *format, ...) {
    (void)format;
    /* Upstream diagnostics may contain URLs, headers, passwords and hashes.
     * Never route these into logcat/Binder's ordinary diagnostic stream. */
    if (priority <= LOG_ERR) redsocks_engine_error("cntlm connection or protocol failure");
}
static void wipe_free(char *text) {
    if (text) { OPENSSL_cleanse(text, strlen(text)); free(text); }
}
static int bool_option(config_t cf, const char *key) {
    char *value = config_pop(cf, key);
    int yes = 0;
    if (value) {
        if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcmp(value, "1")) yes = 1;
        else if (strcasecmp(value, "no") && strcasecmp(value, "false") && strcmp(value, "0")) yes = -1;
    }
    free(value); return yes;
}
static int text_option(config_t cf, const char *key, char *out, size_t capacity) {
    char *text = config_pop(cf, key);
    if (!text) return 0;
    if (strlen(text) >= capacity) { wipe_free(text); return -1; }
    memcpy(out, text, strlen(text)+1);
    wipe_free(text); return 1;
}
static int hash_option(config_t cf, const char *key, char *out) {
    char text[33] = {0};
    int present = text_option(cf, key, text, sizeof(text));
    if (present <= 0) return present;
    if (strlen(text) != 32) { OPENSSL_cleanse(text, sizeof(text)); return -1; }
    for (int i = 0; i < 16; ++i) {
        if (!isxdigit((unsigned char)text[2*i]) || !isxdigit((unsigned char)text[2*i+1])) {
            OPENSSL_cleanse(text, sizeof(text)); return -1;
        }
        char pair[3] = { text[2*i], text[2*i+1], 0 }, *end;
        long value = strtol(pair, &end, 16);
        if (*end) { OPENSSL_cleanse(text, sizeof(text)); return -1; }
        out[i] = value;
    }
    OPENSSL_cleanse(text, sizeof(text));
    return 1;
}
static int auth_mode(struct auth_s *creds, const char *mode) {
    creds->hashnt = creds->hashlm = creds->hashntlm2 = 0;
    if (!mode || !*mode || !strcasecmp(mode, "ntlmv2")) creds->hashntlm2 = 1;
    else if (!strcasecmp(mode, "ntlm2sr")) creds->hashnt = 2;
    else if (!strcasecmp(mode, "ntlm")) creds->hashnt = creds->hashlm = 1;
    else if (!strcasecmp(mode, "nt")) creds->hashnt = 1;
    else if (!strcasecmp(mode, "lm")) creds->hashlm = 1;
    else return -1;
    return 0;
}
static void *run_worker(void *arg) {
    worker *w = arg;
    jmp_buf failure;
    failure_target = &failure;
    struct thread_arg_s *data = calloc(1, sizeof(*data));
    if (!data) goto done;
    data->fd = w->fd; data->addr = w->peer; data->target = w->target;
    if (setjmp(failure)) { cntlm_io_close_thread(); goto done; }
    if (__atomic_load_n(&stopped, __ATOMIC_ACQUIRE) || cntlm_io_adopt(w->fd, w->prefix, w->prefix_len)) {
        close(w->fd); free(data); goto done;
    }
    if (w->mode == 1) tunnel_thread(data);       /* consumes data + accepted fd */
    else if (w->mode == 2) socks5_thread(data);
    else proxy_thread(data);
done:
    free(w->prefix); w->prefix = NULL;
    failure_target = NULL;
    __atomic_store_n(&w->done, 1, __ATOMIC_RELEASE);
    return NULL;
}
static int launch(int fd, const struct sockaddr *peer, int mode,
    const char *target, const void *prefix, size_t length) {
    if (!enabled || __atomic_load_n(&stopped, __ATOMIC_ACQUIRE) ||
        acl_check(rules, (struct sockaddr *)peer) != ACL_ALLOW) return -1;
    size_t count = 0;
    for (worker *w = workers; w; w = w->next) if (!__atomic_load_n(&w->done, __ATOMIC_ACQUIRE)) ++count;
    if (count >= 256) { errno = EBUSY; return -1; }
    worker *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    w->fd = fd; w->mode = mode;
    memcpy(&w->peer, peer, peer->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
    if (target && !(w->target = strdup(target))) goto fail;
    if (length) {
        w->prefix = malloc(length);
        if (!w->prefix) goto fail;
        memcpy(w->prefix, prefix, length); w->prefix_len = length;
    }
    if (pthread_create(&w->thread, NULL, run_worker, w)) goto fail;
    w->next = workers; workers = w;
    return 0;
fail:
    free(w->target); free(w->prefix); free(w); return -1;
}
int cntlm_embed_accept(int fd, const struct sockaddr_in *peer,
    const char *authority, const void *prefix, size_t length) {
    return launch(fd, (const struct sockaddr *)peer, authority ? 1 : 0, authority, prefix, length);
}
static void reap(int fd, short what, void *arg) {
    (void)fd; (void)what; (void)arg;
    worker **link = &workers;
    while (*link) {
        worker *w = *link;
        if (!__atomic_load_n(&w->done, __ATOMIC_ACQUIRE)) { link = &w->next; continue; }
        pthread_join(w->thread, NULL);
        *link = w->next; free(w->target); free(w);
    }
}
static void accept_extra(int fd, short what, void *arg) {
    (void)what;
    listener *l = arg;
    union sock_addr peer; socklen_t size = sizeof(peer);
    int accepted = accept(fd, (struct sockaddr *)&peer, &size);
    if (accepted >= 0 && launch(accepted, &peer.addr, l->mode, l->target, NULL, 0)) close(accepted);
}
static int parse_port(const char *value) {
    if (!value || !*value || strspn(value, "0123456789") != strlen(value)) return -1;
    char *end; errno = 0;
    long port = strtol(value, &end, 10);
    return errno || *end || port < 1 || port > 65535 ? -1 : (int)port;
}
static char *unbracket(char *host) {
    size_t length = strlen(host);
    if (length > 2 && *host == '[' && host[length-1] == ']') {
        host[length-1] = 0; ++host;
    }
    return *host && !strpbrk(host, "[] \t\r\n") ? host : NULL;
}
static int add_listeners(config_t cf, const char *key, int mode, int gateway,
    struct event_base *base, int bind_ports) {
    char *text;
    while ((text = config_pop(cf, key))) {
        char *parts[4] = { text }, *host = NULL, *target = NULL;
        int count = 1, depth = 0, port, valid = 1;
        plist_t bound = NULL;
        struct addrinfo *addresses = NULL;
        for (char *c = text; *c; ++c) {
            if (*c == '[') { if (depth++) valid = 0; }
            else if (*c == ']') { if (--depth) valid = 0; }
            else if (*c == ':' && !depth) {
                if (count == 4) { valid = 0; break; }
                *c = 0; parts[count++] = c + 1;
            }
        }
        if (!valid || depth) goto fail;
        if (mode == 1) {
            if (count != 3 && count != 4) goto fail;
            int offset = count == 4;
            if (offset && !(host = unbracket(parts[0]))) goto fail;
            port = parse_port(parts[offset]);
            char *remote = unbracket(parts[offset+1]);
            int remote_port = parse_port(parts[offset+2]);
            if (!remote || remote_port < 0) goto fail;
            size_t capacity = strlen(remote) + 16;
            target = malloc(capacity);
            if (!target) goto fail;
            snprintf(target, capacity, strchr(remote, ':') ? "[%s]:%d" : "%s:%d", remote, remote_port);
        } else {
            if (count != 1 && count != 2) goto fail;
            if (count == 2 && !(host = unbracket(parts[0]))) goto fail;
            port = parse_port(parts[count-1]);
        }
        if (port < 0) goto fail;
        if (!bind_ports) { free(text); free(target); continue; }
        if (host ? !so_resolv(&addresses, host, port) : so_resolv_wildcard(&addresses, port, gateway)) goto fail;
        if (!so_listen(&bound, addresses, NULL)) goto fail;
        freeaddrinfo(addresses); addresses = NULL;
        while (bound) {
            plist_t node = bound; bound = node->next;
            listener *l = calloc(1, sizeof(*l));
            if (!l) { close(node->key); free(node); goto fail; }
            l->fd = node->key; l->mode = mode; free(node);
            l->next = listeners; listeners = l;
            if (target && !(l->target = strdup(target))) goto fail;
            evutil_make_socket_nonblocking(l->fd);
            evutil_make_socket_closeonexec(l->fd);
            l->event = event_new(base, l->fd, EV_READ | EV_PERSIST, accept_extra, l);
            if (!l->event || event_add(l->event, NULL)) goto fail;
        }
        free(text); free(target); continue;
fail:
        if (addresses) freeaddrinfo(addresses);
        while (bound) { plist_t node = bound; bound = node->next; close(node->key); free(node); }
        free(text); free(target); return -1;
    }
    return 0;
}
int cntlm_embed_init(int fd, struct event_base *base, int bind_ports) {
    __atomic_store_n(&stopped, 0, __ATOMIC_RELEASE);
    if (fd < 0) return 0;
    enabled = 1;
    jmp_buf failure; failure_target = &failure;
    config_t volatile cf = NULL;
    char mode[32] = {0}, password[4096] = {0}, flags[32] = {0};
    if (setjmp(failure)) {
        config_close(cf); OPENSSL_cleanse(password, sizeof(password));
        failure_target = NULL; return -1;
    }
    lseek(fd, 0, SEEK_SET);
    cf = config_open_fd(fd);
    if (!cf) goto fail;
    g_creds = new_auth();
    if (!g_creds) goto fail;
    if (text_option(cf, "Username", g_creds->user, sizeof(g_creds->user)) < 0 ||
        text_option(cf, "Domain", g_creds->domain, sizeof(g_creds->domain)) < 0 ||
        text_option(cf, "Workstation", g_creds->workstation, sizeof(g_creds->workstation)) < 0 ||
        text_option(cf, "Auth", mode, sizeof(mode)) < 0 ||
        text_option(cf, "Flags", flags, sizeof(flags)) < 0 || auth_mode(g_creds, mode)) goto fail;
    int has_password = text_option(cf, "Password", password, sizeof(password));
    if (has_password < 0) goto fail;
    if (!*g_creds->workstation) gethostname(g_creds->workstation, sizeof(g_creds->workstation)-1);
    int nt = hash_option(cf, "PassNT", g_creds->passnt);
    int lm = hash_option(cf, "PassLM", g_creds->passlm);
    int v2 = hash_option(cf, "PassNTLMv2", g_creds->passntlm2);
    if (nt < 0 || lm < 0 || v2 < 0) goto fail;
    if (has_password) {
        char *hash;
        if (!nt) { hash = ntlm_hash_nt_password(password); memcpy(g_creds->passnt, hash, 21); OPENSSL_cleanse(hash, 21); free(hash); }
        if (!lm) { hash = ntlm_hash_lm_password(password); memcpy(g_creds->passlm, hash, 21); OPENSSL_cleanse(hash, 21); free(hash); }
        if (!v2) { hash = ntlm2_hash_password(g_creds->user, g_creds->domain, password); memcpy(g_creds->passntlm2, hash, 16); OPENSSL_cleanse(hash, 16); free(hash); }
        nt = lm = v2 = 1;
    }
    OPENSSL_cleanse(password, sizeof(password));
    if (*flags) {
        char *end; unsigned long value = strtoul(flags, &end, 0);
        if (*end || value > UINT32_MAX) goto fail;
        g_creds->flags = U32LE(value);
    }
    ntlmbasic = bool_option(cf, "NTLMToBasic");
    if (ntlmbasic < 0) goto fail;
    if (!ntlmbasic && ((g_creds->hashnt && !nt) || (g_creds->hashlm && !lm) || (g_creds->hashntlm2 && !v2))) {
        redsocks_engine_error("cntlm Auth requires a matching password/hash"); goto fail;
    }
    char *text;
    while ((text = config_pop(cf, "Proxy"))) { int ok = parent_add(text, 0); free(text); if (!ok) goto fail; }
    char *pac_file = config_pop(cf, "Pac");
    if (pac_file) {
        int ok = pac_init() && pac_parse_file(pac_file);
        free(pac_file);
        if (!ok) { redsocks_engine_error("Invalid cntlm PAC configuration"); goto fail; }
        pac_initialized = 1;
    }
    if (!parent_available() && !pac_initialized) { redsocks_engine_error("cntlm requires Proxy or Pac"); goto fail; }
    /* Keep ACL file order, including interleaved Allow/Deny. */
    for (hlist_t p = cf->options; p; p = p->next)
        if (!strcasecmp(p->key, "Allow") || !strcasecmp(p->key, "Deny"))
            if (!acl_add(&rules, p->value, !strcasecmp(p->key, "Allow") ? ACL_ALLOW : ACL_DENY)) goto fail;
    while ((text = config_pop(cf, "Allow"))) free(text);
    while ((text = config_pop(cf, "Deny"))) free(text);
    while ((text = config_pop(cf, "Header"))) {
        if (!is_http_header(text)) { free(text); goto fail; }
        header_list = hlist_add(header_list, get_http_header_name(text), get_http_header_value(text), HLIST_NOALLOC, HLIST_NOALLOC);
        free(text);
    }
    while ((text = config_pop(cf, "NoProxy"))) { noproxy_list = noproxy_add(noproxy_list, text); free(text); }
    const char *user_keys[] = { "SOCKS5User", "SOCKS5Users" };
    for (size_t i = 0; i < 2; ++i) while ((text = config_pop(cf, user_keys[i]))) {
        size_t text_length = strlen(text);
        char *colon = strchr(text, ':');
        if (!colon) { wipe_free(text); goto fail; }
        *colon++ = 0;
        users_list = hlist_add(users_list, text, colon, HLIST_ALLOC, HLIST_ALLOC);
        OPENSSL_cleanse(text, text_length); free(text);
    }
    char size[32] = {0};
    if (text_option(cf, "ISAScannerSize", size, sizeof(size)) < 0) goto fail;
    if (*size) {
        char *end; errno = 0;
        scanner_plugin_maxsize = strtol(size, &end, 10);
        if (errno || *end || scanner_plugin_maxsize < 0) goto fail;
        scanner_plugin = 1;
    }
    while ((text = config_pop(cf, "ISAScannerAgent"))) {
        scanner_plugin = 1;
        if (!scanner_plugin_maxsize) scanner_plugin_maxsize = 1;
        char *pattern = malloc(strlen(text)+3);
        if (!pattern) { free(text); goto fail; }
        sprintf(pattern, "*%s*", text); free(text);
        scanner_agent_list = plist_add(scanner_agent_list, 0, pattern);
    }
    int gateway = bool_option(cf, "Gateway");
    if (gateway < 0) goto fail;
    if (add_listeners(cf, "Listen", 0, gateway, base, bind_ports) ||
        add_listeners(cf, "Tunnel", 1, gateway, base, bind_ports) ||
        add_listeners(cf, "SOCKS5Proxy", 2, gateway, base, bind_ports)) goto fail;
    /* Process controls have no meaning inside a RootService and are rejected. */
    if (config_count(cf)) { redsocks_engine_error("Unsupported or duplicate cntlm configuration option"); goto fail; }
    config_close(cf);
    if (bind_ports) {
        reaper = event_new(base, -1, EV_PERSIST, reap, NULL);
        struct timeval interval = { 0, 500000 };
        if (!reaper || event_add(reaper, &interval)) goto fail_no_cf;
    }
    failure_target = NULL; return 0;
fail:
    OPENSSL_cleanse(password, sizeof(password));
    config_close(cf);
fail_no_cf:
    failure_target = NULL; return -1;
}
int cntlm_embed_enabled(void) { return enabled; }
int cntlm_embed_tls(int enabled_tls, const char *host) { return cntlm_io_tls(enabled_tls, host); }
void cntlm_embed_stop(void) {
    __atomic_store_n(&stopped, 1, __ATOMIC_RELEASE);
    cntlm_io_stop();
}
void cntlm_embed_fini(void) {
    if (reaper) event_free(reaper);
    reaper = NULL;
    while (listeners) {
        listener *l = listeners; listeners = l->next;
        if (l->event) event_free(l->event);
        close(l->fd); free(l->target); free(l);
    }
    while (workers) {
        worker *w = workers; workers = w->next;
        pthread_join(w->thread, NULL); free(w->target); free(w->prefix); free(w);
    }
    for (plist_t cached = connection_list; cached; cached = cached->next)
        if (cached->aux) OPENSSL_cleanse(cached->aux, sizeof(struct auth_s));
    connection_list = plist_free(connection_list);
    threads_list = plist_free(threads_list);
    cntlm_io_reset();
    header_list = hlist_free(header_list);
    for (hlist_t user = users_list; user; user = user->next)
        if (user->value) OPENSSL_cleanse(user->value, strlen(user->value));
    users_list = hlist_free(users_list);
    scanner_agent_list = plist_free(scanner_agent_list);
    noproxy_list = plist_free(noproxy_list);
    parent_free();
    pac_cleanup(); pac_initialized = 0;
    rules = plist_free(rules);
    if (g_creds) { OPENSSL_cleanse(g_creds, sizeof(*g_creds)); free(g_creds); }
    g_creds = NULL;
    ntlmbasic = serialize = scanner_plugin = 0;
    scanner_plugin_maxsize = 0;
    enabled = 0;
}
static void hex(const unsigned char *bytes, char *out) {
    static const char digits[] = "0123456789ABCDEF";
    for (int i = 0; i < 16; ++i) { out[2*i] = digits[bytes[i] >> 4]; out[2*i+1] = digits[bytes[i] & 15]; }
    out[32] = 0;
}
static int hashes_impl(const char *user, const char *domain, const char *password, char *out, size_t length) {
    if (!user || !domain || !password || !out || length < 140) return -1;
    char lm[33], nt[33], v2[33];
    char *hash = ntlm_hash_lm_password((char *)password); if (!hash) return -1; hex((unsigned char *)hash, lm); OPENSSL_cleanse(hash, 21); free(hash);
    hash = ntlm_hash_nt_password((char *)password); if (!hash) return -1; hex((unsigned char *)hash, nt); OPENSSL_cleanse(hash, 21); free(hash);
    hash = ntlm2_hash_password((char *)user, (char *)domain, (char *)password); if (!hash) return -1; hex((unsigned char *)hash, v2); OPENSSL_cleanse(hash, 16); free(hash);
    snprintf(out, length, "PassLM %s\nPassNT %s\nPassNTLMv2 %s\n", lm, nt, v2);
    OPENSSL_cleanse(lm, sizeof(lm)); OPENSSL_cleanse(nt, sizeof(nt)); OPENSSL_cleanse(v2, sizeof(v2)); return 0;
}
static int detect_impl(const char *url, char *out, size_t capacity) {
    if (!enabled || !url || strncmp(url, "http://", 7)) return -1;
    const char *modes[] = { "NTLMv2", "NTLM2SR", "NT", "NTLM", "LM" };
    size_t used = 0;
    for (int i = 0; i < 5; ++i) {
        struct auth_s *creds = new_auth(); if (!creds) return -1;
        rr_data_t request = new_rr_data(), response = new_rr_data();
        request->req = 1; request->empty = 0;
        request->method = strdup("HEAD"); request->url = strdup(url); request->http = strdup("HTTP/1.1");
        const char *slash = strchr(url+7, '/');
        char *host = slash ? substr(url+7, 0, slash-(url+7)) : strdup(url+7);
        request->headers = hlist_add(NULL, "Host", host, HLIST_ALLOC, HLIST_NOALLOC);
        request->hostname = strdup(host); request->http_version = 11;
        int fd = proxy_connect(creds, url, host);
        auth_mode(creds, modes[i]);
        int ok = fd >= 0 && proxy_authenticate(&fd, request, response, creds);
        if (ok && response->code == 407) {
            reset_rr_data(response);
            ok = headers_send(fd, request) && headers_recv(fd, response);
        }
        int code = ok ? response->code : 0;
        if (used < capacity) used += snprintf(out+used, capacity-used, "%s %s (%d)\n", modes[i], ok && code != 407 ? "accepted" : "failed", code);
        if (fd >= 0) close(fd);
        OPENSSL_cleanse(creds, sizeof(*creds)); free(creds); free_rr_data(&request); free_rr_data(&response);
    }
    return used < capacity ? 0 : -1;
}

int cntlm_embed_hashes(const char *user, const char *domain, const char *password, char *out, size_t capacity) {
    jmp_buf failure;
    jmp_buf *previous = failure_target;
    failure_target = &failure;
    int result = -1;
    if (!setjmp(failure)) result = hashes_impl(user, domain, password, out, capacity);
    failure_target = previous;
    if (result && out && capacity) OPENSSL_cleanse(out, capacity);
    return result;
}
int cntlm_embed_detect(const char *url, char *out, size_t capacity) {
    jmp_buf failure;
    jmp_buf *previous = failure_target;
    failure_target = &failure;
    int result = -1;
    if (!setjmp(failure)) result = detect_impl(url, out, capacity);
    else cntlm_io_close_thread();
    failure_target = previous;
    if (result && out && capacity) OPENSSL_cleanse(out, capacity);
    return result;
}
