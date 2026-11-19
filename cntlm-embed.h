#ifndef REDSOCKS_CNTLM_EMBED_H
#define REDSOCKS_CNTLM_EMBED_H
#include <stddef.h>
#include <netinet/in.h>
struct event_base;
/* Shared context, initialized once for all HTTP/CONNECT/extra listeners. */
int cntlm_embed_init(int fd, struct event_base *base, int listeners);
void cntlm_embed_stop(void);
void cntlm_embed_fini(void);
int cntlm_embed_enabled(void);
int cntlm_embed_tls(int enabled, const char *host);
/* Ownership of fd transfers only on success. Prefix contains sniffed bytes. */
int cntlm_embed_accept(int fd, const struct sockaddr_in *peer,
    const char *authority, const void *prefix, size_t length);
int cntlm_embed_hashes(const char *, const char *, const char *, char *, size_t);
int cntlm_embed_detect(const char *, char *, size_t);
#endif
