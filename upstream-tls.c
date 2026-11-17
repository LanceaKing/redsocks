#include <event.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "upstream-tls.h"
#include "engine-internal.h"

SSL_CTX *redsocks_tls_context(const char *ca_file)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) goto fail;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    if (ca_file && *ca_file) {
        if (!SSL_CTX_load_verify_locations(ctx, ca_file, NULL)) goto fail;
    } else if (redsocks_trust_fd() >= 0) {
        int fd = dup(redsocks_trust_fd());
        if (fd < 0) goto fail;
        lseek(fd, 0, SEEK_SET);
        BIO *bio = BIO_new_fd(fd, BIO_CLOSE);
        if (!bio) { close(fd); goto fail; }
        X509 *cert;
        int count = 0;
        while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
            if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert)) ++count;
            X509_free(cert);
        }
        BIO_free(bio);
        ERR_clear_error();
        if (!count) goto fail;
    } else if (!SSL_CTX_set_default_verify_paths(ctx)) goto fail;
    return ctx;
fail:
    SSL_CTX_free(ctx);
    redsocks_engine_error("TLS trust initialization failed");
    return NULL;
}

SSL *redsocks_tls_session(SSL_CTX *ctx, const char *host)
{
    if (!host || !*host) return NULL;
    SSL *ssl = SSL_new(ctx);
    unsigned char address[16];
    if (!ssl) return NULL;
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (inet_pton(AF_INET, host, address) == 1 || inet_pton(AF_INET6, host, address) == 1) {
        if (!X509_VERIFY_PARAM_set1_ip_asc(param, host)) goto fail;
    } else {
        if (!SSL_set_tlsext_host_name(ssl, host) || !SSL_set1_host(ssl, host)) goto fail;
    }
    return ssl;
fail:
    SSL_free(ssl);
    return NULL;
}

void redsocks_tls_close(struct bufferevent *bev)
{
    SSL *ssl = bufferevent_openssl_get_ssl(bev);
    /* Write close_notify only after the application output has drained. Never
     * wait for the peer's alert during half-close or engine shutdown. */
    if (ssl) SSL_shutdown(ssl);
}
