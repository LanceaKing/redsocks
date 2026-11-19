/* Repeated write EOF must preserve unread TLS response records. */
#include "redsocks.h"
#include "event-cleanup.h"
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "TLS half-close failed at line %d: %s\n", __LINE__, #condition); \
    ERR_print_errors_fp(stderr); goto cleanup; } } while (0)

static int handshake(SSL *client, SSL *server)
{
    int client_done = 0, server_done = 0;
    for (int i = 0; i < 1000 && !(client_done && server_done); ++i) {
        SSL *peers[] = {client, server};
        int *done[] = {&client_done, &server_done};
        for (int j = 0; j < 2; ++j) {
            if (*done[j]) continue;
            int result = SSL_do_handshake(peers[j]);
            if (result == 1) *done[j] = 1;
            else {
                int error = SSL_get_error(peers[j], result);
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return 0;
            }
        }
    }
    return client_done && server_done;
}

static int run_case(const char *certificate, const char *key, int version)
{
    static const char response[] = "TLS response queued before repeated write EOF";
    SSL_CTX *client_ctx = NULL, *server_ctx = NULL;
    SSL *client_ssl = NULL, *server_ssl = NULL;
    struct event_base *base = NULL;
    struct bufferevent *bev = NULL;
    redsocks_instance instance = {0};
    redsocks_client client = {0};
    int sockets[2] = {-1, -1}, failed = 1;
    char received[sizeof(response)];

    client_ctx = SSL_CTX_new(TLS_client_method());
    server_ctx = SSL_CTX_new(TLS_server_method());
    CHECK(client_ctx && server_ctx);
    CHECK(SSL_CTX_load_verify_locations(client_ctx, certificate, NULL));
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
    CHECK(SSL_CTX_set_min_proto_version(client_ctx, version));
    CHECK(SSL_CTX_set_max_proto_version(client_ctx, version));
    CHECK(SSL_CTX_set_min_proto_version(server_ctx, version));
    CHECK(SSL_CTX_set_max_proto_version(server_ctx, version));
    CHECK(SSL_CTX_use_certificate_file(server_ctx, certificate, SSL_FILETYPE_PEM));
    CHECK(SSL_CTX_use_PrivateKey_file(server_ctx, key, SSL_FILETYPE_PEM));
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    CHECK(evutil_make_socket_nonblocking(sockets[0]) == 0);
    CHECK(evutil_make_socket_nonblocking(sockets[1]) == 0);
    client_ssl = SSL_new(client_ctx);
    server_ssl = SSL_new(server_ctx);
    CHECK(client_ssl && server_ssl);
    CHECK(SSL_set_fd(client_ssl, sockets[0]));
    CHECK(SSL_set_fd(server_ssl, sockets[1]));
    SSL_set_connect_state(client_ssl);
    SSL_set_accept_state(server_ssl);
    CHECK(handshake(client_ssl, server_ssl));
    CHECK(SSL_write(server_ssl, response, sizeof(response)) == (int)sizeof(response));
    base = event_base_new();
    CHECK(base);
    bev = bufferevent_openssl_socket_new(base, sockets[0], client_ssl, BUFFEREVENT_SSL_OPEN, 0);
    CHECK(bev);
    instance.config.tls = true;
    client.instance = &instance;
    client.relay = bev;
    CHECK(redsocks_shutdown(&client, bev, SHUT_WR));
    CHECK(redsocks_shutdown(&client, bev, SHUT_WR));
    CHECK(SSL_read(client_ssl, received, sizeof(received)) == (int)sizeof(response));
    CHECK(memcmp(received, response, sizeof(response)) == 0);
    CHECK(SSL_shutdown(server_ssl) >= 0);
    int result = SSL_read(client_ssl, received, sizeof(received));
    CHECK(result == 0 && SSL_get_error(client_ssl, result) == SSL_ERROR_ZERO_RETURN);
    fprintf(stderr, "version=%d write_eofs=2 response_bytes=%zu authenticated_eof=1\n", version, sizeof(response));
    failed = 0;
cleanup:
    if (bev) {
        redsocks_bufferevent_free(bev);
        client_ssl = NULL;
        sockets[0] = -1;
    }
    SSL_free(client_ssl);
    SSL_free(server_ssl);
    if (sockets[0] >= 0) close(sockets[0]);
    if (sockets[1] >= 0) close(sockets[1]);
    if (base && redsocks_event_base_free(base)) failed = 1;
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    return failed;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s certificate.pem key.pem\n", argv[0]);
        return 2;
    }
    int failed = run_case(argv[1], argv[2], TLS1_2_VERSION);
    failed += run_case(argv[1], argv[2], TLS1_3_VERSION);
    return failed ? 1 : 0;
}
