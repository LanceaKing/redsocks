/* Event storage belongs to the engine; bufferevents remain opaque. */
#ifndef REDSOCKS_ENGINE_COMPAT_H
#define REDSOCKS_ENGINE_COMPAT_H
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include "engine-internal.h"
static inline struct bufferevent *redsocks_bev_new(int fd, bufferevent_data_cb rd,
    bufferevent_data_cb wr, bufferevent_event_cb err, void *arg) {
    struct bufferevent *b = bufferevent_socket_new(redsocks_event_base(), fd, 0);
    if (b) bufferevent_setcb(b, rd, wr, err, arg);
    return b;
}
#endif
