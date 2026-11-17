# Shared redsocks engine

Initialize the pinned cntlm fork and build on Linux:

```sh
git submodule update --init --recursive
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
```

The build needs CMake 3.22.1+, a C compiler, libevent with OpenSSL support,
OpenSSL development headers, and pthreads. Android builds supply their pinned
static libevent/OpenSSL targets from ProxyDroid's parent CMake project.

## C caller

Save this as `caller.c` beside the repository and pass paths to redsocks.conf,
an optional PEM trust bundle, and an optional cntlm.conf:

```c
#include "engine.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) return 2;
    redsocks_engine_options options = {
        .config_fd = open(argv[1], O_RDONLY),
        .trust_fd = argc > 2 ? open(argv[2], O_RDONLY) : -1,
        .cntlm_fd = argc > 3 ? open(argv[3], O_RDONLY) : -1,
        .socket_mark = 0,
    };
    if (options.config_fd < 0 || (argc > 2 && options.trust_fd < 0) ||
        (argc > 3 && options.cntlm_fd < 0)) return 2;
    redsocks_engine *engine = redsocks_engine_create();
    int result = redsocks_engine_start(engine, &options);
    close(options.config_fd);
    if (options.trust_fd >= 0) close(options.trust_fd);
    if (options.cntlm_fd >= 0) close(options.cntlm_fd);
    if (!result) {
        puts("ready; press Enter to stop");
        getchar();
        redsocks_engine_request_stop(engine);
        result = redsocks_engine_join(engine);
    } else {
        char error[512];
        redsocks_engine_diagnostics(engine, error, sizeof(error));
        fprintf(stderr, "%s\n", error);
    }
    redsocks_engine_destroy(engine);
    return result ? 1 : 0;
}
```

```sh
cc -std=c99 -I. caller.c -Lbuild -lredsocks -Wl,-rpath,"$PWD/build" -o caller
./caller redsocks.conf trust.pem cntlm.conf
```

The caller serializes lifecycle operations for each opaque handle; stop may be
requested from another thread. Start returns after all listeners are bound.
Input descriptors are borrowed and duplicated before return. Only one engine
context may run in a process. The host must stop/join before destroying the
handle. The library does not daemonize, fork, call exit, alter uid/chroot,
register process signal handlers, or change process-wide file limits.

`redsocks_engine_validate` checks configuration without binding listeners.
`redsocks_engine_hashes` returns explicit caller-requested LM/NT/NTLMv2 hashes.
`redsocks_engine_detect` runs the dialect probes in an isolated engine context;
it requires the same stopped-handle ownership as validate/start.

## Configuration and CLI

```conf
base { redirector = iptables; daemon = off; log_info = off; }
redsocks {
    local_ip = 127.0.0.1; local_port = 12345;
    ip = 192.0.2.10; port = 443;
    type = http-connect;
    tls = on;
    tls_host = "proxy.example.com";
    cntlm_context = "default";
}
```

`tls_host` supplies the upstream certificate identity/SNI, independently of
the target site's sniffed SNI. Numeric identities use IP verification and no
DNS SNI. TLS verification is mandatory. Supply PEM system trust anchors through
`trust_fd`/`-C`, or use OS OpenSSL trust defaults on Linux. `tls_ca` can select
a PEM bundle in a standalone configuration. TLS connections disable splice.
Omit `cntlm_context` to use the existing Basic/Digest logic over TLS instead.

Example `cntlm.conf` (replace the example credentials):

```conf
Proxy proxy.example.com:443
Username User
Domain Domain
Password "example-password"
Auth NTLMv2
# Optional repeated Proxy, Listen, Tunnel, NoProxy, Allow/Deny and Header entries
# Listen 127.0.0.1:3128
# SOCKS5Proxy 127.0.0.1:1080
# SOCKS5User local-user:local-password
# Tunnel 127.0.0.1:8443:target.example.com:443
```

The context retains cntlm's LM/NT/NTLM/NTLM2SR/NTLMv2 dialects, hash inputs,
NTLMToBasic, authenticated stream cache, parent failover, NoProxy, ordered ACLs,
header overrides, additional services, ISA scanner and PAC modules. Additional
services use the same transport/authentication context. Windows SSPI and
platform GSS/Kerberos are not enabled in this Android portable target. Process
controls such as User/PidFile/daemonization are rejected by the embedding host.
The fork's interface and focused unit tests are documented in
[../cntlm/EMBEDDING.md](../cntlm/EMBEDDING.md).

```sh
build/redsocks -c redsocks.conf -n cntlm.conf -C trust.pem -t
build/redsocks -c redsocks.conf -n cntlm.conf -C trust.pem
printf '%s\n' 'example-password' | build/redsocks -H User Domain
build/redsocks -c redsocks.conf -n cntlm.conf -C trust.pem -M http://target.example.com/
```

The CLI blocks termination signals only in its own process; SIGINT/SIGTERM
request shared-engine shutdown. Password hash output is returned only through
the explicit hash API/command and contains credential material.

## Verification

The protocol suite uses actual loopback sockets and a generated CA. It checks
SNI/IP identities, certificate rejection before authentication, buffered data,
all NTLM dialects over plaintext/TLS, same-stream Type1/2/3, closed-407 restart,
Type2 bounds, one-time POST submission, cached TLS streams, extra listeners,
SOCKS5 fragmentation, NTLMToBasic, direct routes, ACLs and repeated cleanup.

```sh
REDSOCKS_BINARY="$PWD/build/redsocks" tests/run -k engine
```

Use `tests/run` without selection for the original Linux namespace regression
suite as well; its additional system dependencies are listed in the README.
These checks establish build and local protocol behavior. Android service,
iptables, Binder death and live upstream acceptance require device validation.
