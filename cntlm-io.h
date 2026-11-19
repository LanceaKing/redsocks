#ifndef REDSOCKS_CNTLM_IO_H
#define REDSOCKS_CNTLM_IO_H
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdint.h>
#include <stddef.h>
int cntlm_io_adopt(int fd, const void *prefix, size_t length);
int cntlm_io_connect(const struct addrinfo *, const char *proxy_name);
ssize_t cntlm_io_read(int, void *, size_t);
ssize_t cntlm_io_read_exact(int, void *, size_t);
ssize_t cntlm_io_write(int, const void *, size_t);
ssize_t cntlm_io_recv(int, void *, size_t, int);
ssize_t cntlm_io_send(int, const void *, size_t, int);
int cntlm_io_close(int);
int cntlm_io_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int cntlm_io_closed(int);
int cntlm_io_shutdown(int, int);
int cntlm_io_tunnel(int, int);
void cntlm_io_auth_timeout(int, int);
void cntlm_io_stop(void);
void cntlm_io_reset(void);
void cntlm_io_close_thread(void);
int cntlm_io_tls(int, const char *);
uint64_t cntlm_embed_random(void);
void cntlm_embed_fatal(void) __attribute__((noreturn));
void cntlm_embed_log(int, const char *, ...);
#endif
