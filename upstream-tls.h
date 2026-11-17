#ifndef REDSOCKS_UPSTREAM_TLS_H
#define REDSOCKS_UPSTREAM_TLS_H
#include <openssl/ssl.h>
SSL_CTX *redsocks_tls_context(const char *ca_file);
SSL *redsocks_tls_session(SSL_CTX *, const char *host);
void redsocks_tls_close(struct bufferevent *bev);
#endif
