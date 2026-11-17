/* All legacy events are assigned to the engine's explicit base. */
#ifndef REDSOCKS_ENGINE_COMPAT_H
#define REDSOCKS_ENGINE_COMPAT_H
#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include "engine-internal.h"
#undef event_set
#define event_set(ev, fd, events, cb, arg) \
    event_assign((ev), redsocks_event_base(), (fd), (events), (cb), (arg))
#undef evtimer_set
#define evtimer_set(ev, cb, arg) event_set((ev), -1, 0, (cb), (arg))
static inline struct bufferevent *redsocks_bev_new(int fd, evbuffercb rd,
    evbuffercb wr, everrorcb err, void *arg) {
    struct bufferevent *b = bufferevent_socket_new(redsocks_event_base(), fd, 0);
    if (b) bufferevent_setcb(b, rd, wr, err, arg);
    return b;
}
#define bufferevent_new redsocks_bev_new
#endif
