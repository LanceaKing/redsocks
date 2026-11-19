#ifndef REDSOCKS_EVENT_CLEANUP_H
#define REDSOCKS_EVENT_CLEANUP_H

#include <event2/event.h>

/* All application events and bufferevents must be disabled/freed first.
 * bufferevent_free() clears application callbacks, but queued deferred
 * callbacks can still own references. Drain those before freeing the base.
 * NONBLOCK drains every ready batch without waiting for timers or I/O. */
static inline int redsocks_event_base_free(struct event_base *base)
{
    int result = event_base_loop(base, EVLOOP_NONBLOCK);
    event_base_free(base);
    return result < 0 ? -1 : 0;
}

#endif
