#ifndef REDSOCKS_ENGINE_INTERNAL_H
#define REDSOCKS_ENGINE_INTERNAL_H
#include <event2/event.h>
struct event_base *redsocks_event_base(void);
int redsocks_apply_socket_mark(int fd);
void redsocks_engine_error(const char *message);
int redsocks_trust_fd(void);
void redsocks_log_reset(void);
#endif
