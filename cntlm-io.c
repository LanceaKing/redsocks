/* Direct transport adaptation for cntlm's message-aware workers. Each stream
 * owns an explicit private event base and buffered socket/TLS bev. No local
 * proxy, socketpair, or second data pump exists in this path. A cached fd is a
 * stable key for the entire stream (including TLS state and unread bytes). */
#include "cntlm-io.h"
#include "engine-internal.h"
#include "upstream-tls.h"
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

typedef struct stream {
    struct stream *next;
    struct event_base *base;
    struct bufferevent *bev;
    int fd, ready, ended, failed;
    pthread_t owner;
} stream;
static stream *streams;
static pthread_mutex_t streams_mutex = PTHREAD_MUTEX_INITIALIZER;
static int stopping;
static int tls_enabled;
static char tls_name[256];
static SSL_CTX *tls_context;
static int is_stopping(void) { return __atomic_load_n(&stopping, __ATOMIC_ACQUIRE); }
static stream *lookup(int fd) {
    pthread_mutex_lock(&streams_mutex);
    stream *s = streams;
    while (s && s->fd != fd) s = s->next;
    pthread_mutex_unlock(&streams_mutex);
    return s;
}
static void changed(struct bufferevent *bev, void *arg) { (void)bev; (void)arg; }
static void event_cb(struct bufferevent *bev, short what, void *arg) {
    stream *s = arg;
    if (what & BEV_EVENT_CONNECTED) {
        s->ready = 1;
        bufferevent_set_timeouts(bev, NULL, NULL);
    }
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        s->ended = 1;
        if (what & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) s->failed = 1;
        if (!s->ready) redsocks_engine_error("cntlm upstream connect/TLS verification failed");
    }
}
static stream *make_stream(int fd, SSL *ssl, int connected) {
    if (is_stopping() || fd < 0 || fd >= FD_SETSIZE) { errno = EMFILE; return NULL; }
    stream *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->fd = fd;
    s->ready = connected;
    s->owner = pthread_self();
    s->base = event_base_new();
    if (!s->base) { free(s); return NULL; }
    if (ssl) s->bev = bufferevent_openssl_socket_new(s->base, fd, ssl,
        BUFFEREVENT_SSL_CONNECTING, 0);
    else s->bev = bufferevent_socket_new(s->base, fd, 0);
    if (!s->bev) { event_base_free(s->base); free(s); return NULL; }
    evutil_make_socket_nonblocking(fd);
    evutil_make_socket_closeonexec(fd);
    bufferevent_setcb(s->bev, changed, changed, event_cb, s);
    bufferevent_setwatermark(s->bev, EV_READ, 0, 64 * 1024);
    pthread_mutex_lock(&streams_mutex);
    if (is_stopping()) {
        pthread_mutex_unlock(&streams_mutex);
        bufferevent_free(s->bev); event_base_free(s->base); free(s); return NULL;
    }
    s->next = streams; streams = s;
    pthread_mutex_unlock(&streams_mutex);
    bufferevent_enable(s->bev, EV_READ | EV_WRITE);
    return s;
}
int cntlm_io_adopt(int fd, const void *prefix, size_t length) {
    stream *s = make_stream(fd, NULL, 1);
    if (!s) return -1;
    if (length) {
        struct evbuffer *in = bufferevent_get_input(s->bev);
        evbuffer_unfreeze(in, 0);
        int rc = evbuffer_add(in, prefix, length);
        evbuffer_freeze(in, 0);
        if (rc) return -1;
    }
    return 0;
}
int cntlm_io_tls(int enabled, const char *name) {
    if (tls_context && enabled != tls_enabled) return -1;
    tls_enabled = enabled;
    if (name && !*tls_name) snprintf(tls_name, sizeof(tls_name), "%s", name);
    if (enabled && !tls_context) tls_context = redsocks_tls_context(NULL);
    return enabled && !tls_context ? -1 : 0;
}
int cntlm_io_connect(const struct addrinfo *addresses, const char *proxy_name) {
    for (const struct addrinfo *p = addresses; p; p = p->ai_next) {
        if (is_stopping()) { errno = ECANCELED; return -1; }
        if (p->ai_family != AF_INET && p->ai_family != AF_INET6) continue;
        int fd = socket(p->ai_family, SOCK_STREAM, 0);
        if (fd < 0) continue;
        if (redsocks_apply_socket_mark(fd)) { close(fd); continue; }
        SSL *ssl = NULL;
        if (tls_enabled && proxy_name) {
            const char *name = proxy_name;
            unsigned char ip[16];
            if (*tls_name && (inet_pton(AF_INET, proxy_name, ip) == 1 ||
                              inet_pton(AF_INET6, proxy_name, ip) == 1)) name = tls_name;
            ssl = redsocks_tls_session(tls_context, name);
            if (!ssl) { close(fd); return -1; }
        }
        stream *s = make_stream(fd, ssl, 0);
        if (!s) { SSL_free(ssl); close(fd); continue; }
        struct timeval limit = { 10, 0 };
        bufferevent_set_timeouts(s->bev, &limit, &limit);
        if (bufferevent_socket_connect(s->bev, p->ai_addr, p->ai_addrlen)) s->ended = 1;
        while (!s->ready && !s->ended && !is_stopping()) {
            if (event_base_loop(s->base, EVLOOP_ONCE) < 0) { s->ended = 1; break; }
        }
        if (s->ready && !s->ended && !is_stopping()) return fd;
        cntlm_io_close(fd);
    }
    return -1;
}
void cntlm_io_auth_timeout(int fd, int seconds) {
    stream *s = lookup(fd);
    if (s) {
        struct timeval limit = { seconds, 0 };
        bufferevent_set_timeouts(s->bev, seconds ? &limit : NULL, seconds ? &limit : NULL);
    }
}
ssize_t cntlm_io_read(int fd, void *out, size_t length) {
    stream *s = lookup(fd);
    if (!s) return read(fd, out, length);
    s->owner = pthread_self();
    if (!length) return 0;
    struct evbuffer *in = bufferevent_get_input(s->bev);
    while (!evbuffer_get_length(in) && !s->ended && !is_stopping())
        if (event_base_loop(s->base, EVLOOP_ONCE) < 0) { s->ended = 1; break; }
    if (is_stopping()) { errno = ECANCELED; return -1; }
    if (!evbuffer_get_length(in) && s->failed) { errno = EIO; return -1; }
    return evbuffer_remove(in, out, length);
}
ssize_t cntlm_io_read_exact(int fd, void *out, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t got = cntlm_io_read(fd, (char *)out+offset, length-offset);
        if (got <= 0) return offset ? (ssize_t)offset : got;
        offset += got;
    }
    return offset;
}
ssize_t cntlm_io_write(int fd, const void *data, size_t length) {
    stream *s = lookup(fd);
    if (!s) return write(fd, data, length);
    s->owner = pthread_self();
    size_t offset = 0;
    while (offset < length && !s->failed && !is_stopping()) {
        size_t chunk = length-offset > 65536 ? 65536 : length-offset;
        if (bufferevent_write(s->bev, (const char *)data+offset, chunk)) return -1;
        while (evbuffer_get_length(bufferevent_get_output(s->bev)) && !s->failed && !is_stopping())
            if (event_base_loop(s->base, EVLOOP_ONCE) < 0) { s->failed = 1; break; }
        if (!s->failed && !is_stopping()) offset += chunk;
    }
    if (!offset && length) { errno = EPIPE; return -1; }
    return offset;
}
ssize_t cntlm_io_recv(int fd, void *out, size_t length, int flags) {
    stream *s = lookup(fd);
    if (!s) return recv(fd, out, length, flags);
    event_base_loop(s->base, EVLOOP_NONBLOCK | EVLOOP_ONCE);
    struct evbuffer *in = bufferevent_get_input(s->bev);
    if (!evbuffer_get_length(in)) {
        if (s->ended || is_stopping()) return 0;
        if (flags & MSG_DONTWAIT) { errno = EAGAIN; return -1; }
        if (!(flags & MSG_PEEK)) return cntlm_io_read(fd, out, length);
        while (!evbuffer_get_length(in) && !s->ended && !is_stopping()) event_base_loop(s->base, EVLOOP_ONCE);
    }
    return flags & MSG_PEEK ? evbuffer_copyout(in, out, length) : evbuffer_remove(in, out, length);
}
ssize_t cntlm_io_send(int fd, const void *data, size_t length, int flags) {
    (void)flags;
    return cntlm_io_write(fd, data, length);
}
int cntlm_io_closed(int fd) {
    stream *s = lookup(fd);
    if (!s) return fd < 0;
    event_base_loop(s->base, EVLOOP_NONBLOCK | EVLOOP_ONCE);
    return (s->ended && !evbuffer_get_length(bufferevent_get_input(s->bev))) || is_stopping();
}
int cntlm_io_shutdown(int fd, int how) {
    stream *s = lookup(fd);
    SSL *ssl = s ? bufferevent_openssl_get_ssl(s->bev) : NULL;
    if (ssl && how != SHUT_RD) {
        int rc = SSL_shutdown(ssl);
        if (rc >= 0) return 0;
        int error = SSL_get_error(ssl, rc);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) return 0;
        return -1;
    }
    return ssl ? 0 : shutdown(fd, how);
}
int cntlm_io_tunnel(int client, int server) {
    int open[2] = { 1, 1 }, pair[2][2] = { {client, server}, {server, client} };
    char buffer[16384];
    while (open[0] || open[1]) {
        fd_set readable;
        FD_ZERO(&readable);
        for (int i = 0; i < 2; ++i) if (open[i]) FD_SET(pair[i][0], &readable);
        int n = client > server ? client + 1 : server + 1;
        if (cntlm_io_select(n, &readable, NULL, NULL, NULL) < 0) return 0;
        for (int i = 0; i < 2; ++i) if (open[i] && FD_ISSET(pair[i][0], &readable)) {
            ssize_t got = cntlm_io_read(pair[i][0], buffer, sizeof(buffer));
            if (got < 0) return 0;
            if (!got) {
                open[i] = 0;
                if (cntlm_io_shutdown(pair[i][1], SHUT_WR) < 0) return 0;
            } else if (cntlm_io_write(pair[i][1], buffer, got) != got) return 0;
        }
    }
    return 1;
}
int cntlm_io_close(int fd) {
    pthread_mutex_lock(&streams_mutex);
    stream **link = &streams;
    while (*link && (*link)->fd != fd) link = &(*link)->next;
    stream *s = *link;
    if (s) *link = s->next;
    pthread_mutex_unlock(&streams_mutex);
    if (s) {
        SSL *ssl = bufferevent_openssl_get_ssl(s->bev);
        bufferevent_free(s->bev);
        SSL_free(ssl);
        event_base_free(s->base);
        free(s);
    }
    return close(fd);
}
/* Adapt readiness to decrypted buffered data. SSL record fragments and control
 * records are consumed before reporting readability to cntlm's tunnel loop. */
int cntlm_io_select(int n, fd_set *reads, fd_set *writes, fd_set *errors, struct timeval *timeout) {
    fd_set wanted_r, wanted_w;
    FD_ZERO(&wanted_r); FD_ZERO(&wanted_w);
    if (reads) wanted_r = *reads;
    if (writes) wanted_w = *writes;
    long remaining = timeout ? timeout->tv_sec*1000 + timeout->tv_usec/1000 : -1;
    while (!is_stopping()) {
        int ready = 0;
        struct pollfd fds[FD_SETSIZE]; int count = 0;
        if (reads) FD_ZERO(reads);
        if (writes) FD_ZERO(writes);
        if (errors) FD_ZERO(errors);
        for (int fd = 0; fd < n && fd < FD_SETSIZE; ++fd) {
            if (!FD_ISSET(fd, &wanted_r) && !FD_ISSET(fd, &wanted_w)) continue;
            stream *s = lookup(fd);
            if (s) {
                s->owner = pthread_self();
                /* A nonblocking loop can keep dispatching an always-ready
                 * TLS socket. Yield after one iteration so buffered data and
                 * the engine's stop flag are observed between dispatches. */
                event_base_loop(s->base, EVLOOP_NONBLOCK | EVLOOP_ONCE);
                if (reads && FD_ISSET(fd, &wanted_r) && (s->ended || evbuffer_get_length(bufferevent_get_input(s->bev)))) {
                    FD_SET(fd, reads); ++ready;
                }
                if (writes && FD_ISSET(fd, &wanted_w) && !s->ended) { FD_SET(fd, writes); ++ready; }
            }
            fds[count++] = (struct pollfd){ .fd = fd, .events = POLLIN | (FD_ISSET(fd, &wanted_w) ? POLLOUT : 0) };
        }
        if (ready || remaining == 0) return ready;
        int delay = remaining < 0 || remaining > 100 ? 100 : remaining;
        int rc = poll(fds, count, delay);
        if (rc < 0 && errno != EINTR) return -1;
        for (int i = 0; i < count; ++i) if (!lookup(fds[i].fd) && fds[i].revents) {
            if (reads && FD_ISSET(fds[i].fd, &wanted_r)) { FD_SET(fds[i].fd, reads); ++ready; }
            if (writes && FD_ISSET(fds[i].fd, &wanted_w)) { FD_SET(fds[i].fd, writes); ++ready; }
        }
        if (ready) return ready;
        if (remaining > 0) remaining = remaining > delay ? remaining-delay : 0;
    }
    errno = ECANCELED; return -1;
}
void cntlm_io_stop(void) {
    __atomic_store_n(&stopping, 1, __ATOMIC_RELEASE);
    pthread_mutex_lock(&streams_mutex);
    for (stream *s = streams; s; s = s->next) shutdown(s->fd, SHUT_RDWR);
    pthread_mutex_unlock(&streams_mutex);
}
void cntlm_io_close_thread(void) {
    for (;;) {
        pthread_mutex_lock(&streams_mutex);
        int fd = -1;
        for (stream *s = streams; s; s = s->next) if (pthread_equal(s->owner, pthread_self())) { fd = s->fd; break; }
        pthread_mutex_unlock(&streams_mutex);
        if (fd < 0) break;
        cntlm_io_close(fd);
    }
}
void cntlm_io_reset(void) {
    while (streams) cntlm_io_close(streams->fd);
    SSL_CTX_free(tls_context); tls_context = NULL;
    tls_enabled = 0; tls_name[0] = 0;
    __atomic_store_n(&stopping, 0, __ATOMIC_RELEASE);
}
