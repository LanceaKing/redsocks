/* Public, process-safe embedding API. All descriptors are borrowed; start/validate
 * duplicate them before returning. One engine may run in a process at a time. */
#ifndef REDSOCKS_ENGINE_H
#define REDSOCKS_ENGINE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct redsocks_engine redsocks_engine;
enum redsocks_engine_state { REDSOCKS_STOPPED, REDSOCKS_STARTING,
    REDSOCKS_RUNNING, REDSOCKS_STOPPING, REDSOCKS_FAILED };
typedef struct redsocks_engine_options {
    int config_fd;
    int trust_fd;                 /* PEM system anchors, -1 for OS defaults */
    int cntlm_fd;                 /* merged cntlm.conf, -1 if unused */
    uint32_t socket_mark;         /* SO_MARK on every outbound socket */
} redsocks_engine_options;
redsocks_engine *redsocks_engine_create(void);
/* Synchronous readiness: returns only after all listeners are bound, or failure. */
int redsocks_engine_start(redsocks_engine *, const redsocks_engine_options *);
void redsocks_engine_request_stop(redsocks_engine *);
int redsocks_engine_join(redsocks_engine *);
void redsocks_engine_destroy(redsocks_engine *);
int redsocks_engine_get_status(redsocks_engine *);
int redsocks_engine_validate(redsocks_engine *, const redsocks_engine_options *);
size_t redsocks_engine_diagnostics(redsocks_engine *, char *, size_t);
/* Explicit caller-requested diagnostics; hash output contains secrets. */
int redsocks_engine_hashes(const char *user, const char *domain,
    const char *password, char *output, size_t capacity);
int redsocks_engine_detect(redsocks_engine *, const redsocks_engine_options *,
    const char *url, char *output, size_t capacity);
const char *redsocks_engine_build_info(void);
#ifdef __cplusplus
}
#endif
#endif
