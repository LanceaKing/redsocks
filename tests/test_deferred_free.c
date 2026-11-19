/* A stopped event loop must not retain a freed bufferevent's queued reference. */
#include "event-cleanup.h"
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static size_t allocations;
static void *tracked_malloc(size_t size)
{
    void *result = malloc(size);
    if (result) ++allocations;
    return result;
}
static void tracked_free(void *pointer)
{
    if (pointer) --allocations;
    free(pointer);
}
static void *tracked_realloc(void *pointer, size_t size)
{
    if (!pointer) return tracked_malloc(size);
    if (!size) { tracked_free(pointer); return NULL; }
    return realloc(pointer, size);
}

struct test;
struct stream {
    struct test *test;
    struct bufferevent *bev;
    int sockets[2], input_received;
};

struct test {
    struct event_base *base;
    struct stream streams[32];
    int callbacks, stop_before_callback, inputs, stream_count;
};

static void input_changed(struct evbuffer *buffer,
                          const struct evbuffer_cb_info *info, void *arg)
{
    struct stream *stream = arg;
    (void)buffer;
    if (info->n_added) {
        stream->input_received = 1;
        ++stream->test->inputs;
        if (stream->test->stop_before_callback &&
            stream->test->inputs == stream->test->stream_count)
            event_base_loopbreak(stream->test->base);
    }
}

static void read_ready(struct bufferevent *bev, void *arg)
{
    struct stream *stream = arg;
    ++stream->test->callbacks;
    bufferevent_disable(bev, EV_READ | EV_WRITE);
    bufferevent_free(bev);
    stream->bev = NULL;
    event_base_loopbreak(stream->test->base);
}

static int run_case(int deferred, int stop_before_callback, int stream_count)
{
    struct test test = {0};
    int failed = 0, closed = 0, inputs = 0, expected;
    size_t before = allocations;
    test.stop_before_callback = stop_before_callback;
    test.stream_count = stream_count;
    test.base = event_base_new();
    if (!test.base) abort();
    for (int i = 0; i < stream_count; ++i) {
        struct stream *stream = &test.streams[i];
        stream->test = &test;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, stream->sockets) ||
            evutil_make_socket_nonblocking(stream->sockets[0])) abort();
        stream->bev = bufferevent_socket_new(test.base, stream->sockets[0],
            BEV_OPT_CLOSE_ON_FREE | (deferred ? BEV_OPT_DEFER_CALLBACKS : 0));
        if (!stream->bev || !evbuffer_add_cb(bufferevent_get_input(stream->bev),
                                           input_changed, stream)) abort();
        bufferevent_setcb(stream->bev, read_ready, NULL, NULL, stream);
        if (bufferevent_enable(stream->bev, EV_READ) ||
            write(stream->sockets[1], "x", 1) != 1) abort();
    }
    /* Make every socket readable before dispatch, so all read events precede
     * deferred callbacks even on libevent versions that share their queue. */
    if (event_base_dispatch(test.base) < 0) failed = 1;
    expected = deferred && stop_before_callback ? 0 : stream_count;
    for (int i = 0; i < stream_count; ++i) {
        struct bufferevent *bev = test.streams[i].bev;
        inputs += test.streams[i].input_received;
        if (bev) {
            bufferevent_disable(bev, EV_READ | EV_WRITE);
            bufferevent_free(bev);
        }
    }
    if (redsocks_event_base_free(test.base)) failed = 1;
    for (int i = 0; i < stream_count; ++i) {
        errno = 0;
        closed += fcntl(test.streams[i].sockets[0], F_GETFD) == -1 && errno == EBADF;
        close(test.streams[i].sockets[1]);
    }
    fprintf(stderr, "deferred=%d stop_before_callback=%d streams=%d inputs=%d "
            "callbacks=%d expected=%d sockets_closed=%d allocations_before=%zu after=%zu\n",
            deferred, stop_before_callback, stream_count, inputs,
            test.callbacks, expected, closed, before, allocations);
    return failed || test.callbacks != expected || closed != stream_count ||
           inputs != stream_count || allocations != before;
}

int main(void)
{
    int failed = 0;
    event_set_mem_functions(tracked_malloc, tracked_realloc, tracked_free);
    failed += run_case(0, 0, 1);
    failed += run_case(1, 0, 1);
    failed += run_case(1, 1, 1);
    failed += run_case(1, 1, 32);
    return failed ? 1 : 0;
}
