/* Linux regression CLI: lifecycle and forwarding are the shared library's. */
#include "engine.h"
#include "version.h"
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
int main(int argc, char **argv) {
    const char *config = "redsocks.conf", *pidfile = NULL, *cntlm = NULL, *trust = NULL, *detect = NULL;
    int test = 0, hashes = 0, opt;
    while ((opt = getopt(argc, argv, "h?vtHc:p:n:C:M:")) != -1) {
        switch (opt) {
        case 'c': config = optarg; break;
        case 'p': pidfile = optarg; break;
        case 'n': cntlm = optarg; break;
        case 'C': trust = optarg; break;
        case 'M': detect = optarg; break;
        case 'H': hashes = 1; break;
        case 't': test = 1; break;
        case 'v': puts(redsocks_version); puts(redsocks_engine_build_info()); return 0;
        default:
            printf("Usage: %s [-t] [-c redsocks.conf] [-n cntlm.conf] [-C trust.pem] [-p pidfile]\n"
                   "       %s -H user domain   (password from stdin)\n"
                   "       %s -c redsocks.conf -n cntlm.conf -M http://test/url\n", argv[0], argv[0], argv[0]);
            return opt == 'h' || opt == '?' ? 0 : 1;
        }
    }
    if (hashes) {
        char password[4096], output[256];
        if (argc-optind != 2 || !fgets(password, sizeof(password), stdin)) return 1;
        password[strcspn(password, "\r\n")] = 0;
        int result = redsocks_engine_hashes(argv[optind], argv[optind+1], password, output, sizeof(output));
        memset(password, 0, sizeof(password));
        if (!result) fputs(output, stdout);
        memset(output, 0, sizeof(output));
        return result ? 1 : 0;
    }
    sigset_t signals;
    sigemptyset(&signals); sigaddset(&signals, SIGTERM); sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGPIPE); sigaddset(&signals, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &signals, NULL);
    redsocks_engine_options options = { .config_fd = open(config, O_RDONLY),
        .cntlm_fd = cntlm ? open(cntlm, O_RDONLY) : -1, .trust_fd = trust ? open(trust, O_RDONLY) : -1 };
    if (options.config_fd < 0 || (cntlm && options.cntlm_fd < 0) || (trust && options.trust_fd < 0)) {
        perror("configuration/trust"); return 1;
    }
    redsocks_engine *engine = redsocks_engine_create();
    char diagnostic[512];
    int result;
    if (detect) {
        char output[1024] = {0};
        result = redsocks_engine_detect(engine, &options, detect, output, sizeof(output));
        if (!result) fputs(output, stdout);
    } else result = test ? redsocks_engine_validate(engine, &options) : redsocks_engine_start(engine, &options);
    close(options.config_fd);
    if (options.cntlm_fd >= 0) close(options.cntlm_fd);
    if (options.trust_fd >= 0) close(options.trust_fd);
    if (!result && !test && !detect) {
        if (pidfile) { FILE *f = fopen(pidfile, "w"); if (!f) result = -1; else { fprintf(f, "%d\n", getpid()); fclose(f); } }
        while (!result && redsocks_engine_get_status(engine) == REDSOCKS_RUNNING) {
            struct timespec interval = { 0, 200000000 };
            int sig = sigtimedwait(&signals, NULL, &interval);
            if (sig == SIGTERM || sig == SIGINT) break;
        }
        redsocks_engine_request_stop(engine);
        if (redsocks_engine_join(engine)) result = -1;
        if (pidfile) unlink(pidfile);
    }
    redsocks_engine_diagnostics(engine, diagnostic, sizeof(diagnostic));
    if (result) fprintf(stderr, "%s\n", *diagnostic ? diagnostic : "Native engine failed");
    redsocks_engine_destroy(engine);
    return result ? 1 : 0;
}
