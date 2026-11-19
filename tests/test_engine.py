"""Shared-engine lifecycle and real loopback TLS/cntlm protocol regressions."""
import base64
import ctypes
import hashlib
import hmac
import os
from pathlib import Path
import queue
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
from contextlib import contextmanager

import pytest
from test_http_connect_sni import hello, unused_port, receive_exact


class Options(ctypes.Structure):
    _fields_ = [("config_fd", ctypes.c_int), ("trust_fd", ctypes.c_int),
                ("cntlm_fd", ctypes.c_int), ("socket_mark", ctypes.c_uint32)]


@pytest.fixture(scope="session")
def library(redsocks_binary):
    path = Path(os.environ.get("REDSOCKS_LIBRARY", redsocks_binary.parent / "libredsocks.so"))
    lib = ctypes.CDLL(str(path))
    lib.redsocks_engine_create.restype = ctypes.c_void_p
    for name in ("start", "validate"):
        method = getattr(lib, "redsocks_engine_"+name)
        method.argtypes = [ctypes.c_void_p, ctypes.POINTER(Options)]
        method.restype = ctypes.c_int
    for name in ("destroy", "request_stop", "join", "get_status"):
        getattr(lib, "redsocks_engine_"+name).argtypes = [ctypes.c_void_p]
    lib.redsocks_engine_diagnostics.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.redsocks_engine_hashes.argtypes = [ctypes.c_char_p] * 4 + [ctypes.c_size_t]
    return lib


class Engine:
    def __init__(self, lib, tmp, config, cntlm=None, trust=None, start=True):
        self.lib = lib
        self.handle = lib.redsocks_engine_create()
        self.files = []
        for name, data in (("redsocks.conf", config), ("cntlm.conf", cntlm), ("trust.pem", trust)):
            if data is None:
                self.files.append(None)
            else:
                path = tmp / name
                path.write_bytes(data.encode() if isinstance(data, str) else data)
                self.files.append(path.open("rb"))
        self.options = Options(self.files[0].fileno(), self.files[2].fileno() if self.files[2] else -1,
                               self.files[1].fileno() if self.files[1] else -1, 0)
        if start:
            assert self.start() == 0, self.diagnostic()

    def start(self):
        return self.lib.redsocks_engine_start(self.handle, ctypes.byref(self.options))

    def diagnostic(self):
        out = ctypes.create_string_buffer(512)
        self.lib.redsocks_engine_diagnostics(self.handle, out, len(out))
        return out.value.decode()

    def stop(self):
        self.lib.redsocks_engine_request_stop(self.handle)
        return self.lib.redsocks_engine_join(self.handle)

    def close(self):
        if self.handle:
            self.lib.redsocks_engine_destroy(self.handle)
            self.handle = None
        for file in self.files:
            if file:
                file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def config(local, parent, *, tls=False, host="proxy.test", cntlm=False, relay="http-connect", extra=""):
    return f'''base {{ redirector = generic; daemon = off; log_info = off; }}
redsocks {{ local_ip = 127.0.0.1; local_port = {local}; ip = 127.0.0.1; port = {parent};
 type = {relay}; splice = on;
 {('tls = on; tls_host = "'+host+'";') if tls else ''}
 {'cntlm_context = "default";' if cntlm else ''} {extra}
}}
'''


def credentials(parent, mode="NTLMv2", extra=""):
    return f"Proxy 127.0.0.1:{parent}\nUsername User\nDomain Domain\nPassword Password\nAuth {mode}\n{extra}\n"


def headers(conn):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        part = conn.recv(1)
        if not part:
            raise AssertionError("EOF before header block")
        data += part
        assert len(data) <= 65536
    lines = data.decode("ascii").split("\r\n")
    return lines[0], {k.lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:] if line)}


class Server:
    def __init__(self, handler, context=None, connections=1, expect_tls_error=False):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(5)
        self.port = self.socket.getsockname()[1]
        self.errors = queue.Queue()
        self.sni = []
        self.context = context
        if context:
            context.set_servername_callback(lambda conn, name, ctx: self.sni.append(name))
        def serve():
            try:
                for i in range(connections):
                    conn, _ = self.socket.accept()
                    conn.settimeout(5)
                    try:
                        if context:
                            conn = context.wrap_socket(conn, server_side=True)
                        with conn:
                            handler(conn, i)
                    except ssl.SSLError:
                        conn.close()
                        if not expect_tls_error:
                            raise
            except BaseException as e:
                self.errors.put(e)
        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def close(self):
        self.thread.join(7)
        self.socket.close()
        assert not self.thread.is_alive(), "server did not complete"
        if not self.errors.empty():
            raise self.errors.get()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@pytest.fixture(scope="session")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("engine-certificates")
    def run(*args):
        subprocess.run(["openssl", *args], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Engine Test CA", "-keyout", "ca.key", "-out", "ca.pem")
    (root / "index").touch()
    (root / "serial").write_text("1000\n")
    (root / "ca.cnf").write_text(
        "[ca]\ndefault_ca=test\n[test]\ndatabase=index\nnew_certs_dir=.\n"
        "serial=serial\ncertificate=ca.pem\nprivate_key=ca.key\n"
        "default_md=sha256\ndefault_days=2\npolicy=names\n[names]\ncommonName=supplied\n")
    for name, sans in (("valid", "DNS:proxy.test,DNS:localhost,IP:127.0.0.1"),
                       ("wrong", "DNS:other.test"), ("expired", "DNS:proxy.test")):
        run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN="+name, "-keyout", name+".key", "-out", name+".csr")
        (root / "extensions").write_text("subjectAltName="+sans+"\nextendedKeyUsage=serverAuth\n")
        if name == "expired":
            # Fixed past dates work with OpenSSL versions that reject -days -1.
            run("ca", "-batch", "-notext", "-config", "ca.cnf", "-in", name+".csr",
                "-startdate", "20000101000000Z", "-enddate", "20000102000000Z",
                "-extfile", "extensions", "-out", name+".pem")
        else:
            run("x509", "-req", "-in", name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2", "-extfile", "extensions", "-out", name+".pem")
    return root


def tls_context(root, name="valid"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / (name+".pem"), root / (name+".key"))
    return context


def test_repeated_lifecycle_and_failure_cleanup(library, tmp_path):
    # Reuse the same opaque handle after successful stops and parsing failures.
    port = unused_port()
    with Engine(library, tmp_path, config(port, 9), start=False) as engine:
        baseline = len(os.listdir("/proc/self/fd"))
        pipe_handler = signal.getsignal(signal.SIGPIPE)
        for i in range(40):
            assert engine.start() == 0, engine.diagnostic()
            assert library.redsocks_engine_get_status(engine.handle) == 2
            assert engine.stop() == 0
        assert signal.getsignal(signal.SIGPIPE) == pipe_handler
        assert len(os.listdir("/proc/self/fd")) <= baseline+1
        # An open partial section must be freed, even before onexit runs.
        engine.files[0].close()
        file = tmp_path / "invalid.conf"
        file.write_text(config(port, 9) + "redsocks { password = \"secret\"; bad = true;")
        engine.files[0] = file.open("rb")
        engine.options.config_fd = engine.files[0].fileno()
        for i in range(20):
            assert engine.start() == -1
        file.write_text(config(port, 9))
        assert engine.start() == 0, engine.diagnostic()
        assert engine.stop() == 0
        assert len(os.listdir("/proc/self/fd")) <= baseline+1


def test_port_conflict_then_retry_and_single_engine(library, tmp_path):
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0)); occupied.listen()
        port = occupied.getsockname()[1]
        with Engine(library, tmp_path, config(port, 9), start=False) as engine:
            assert engine.start() == -1
            occupied.close()
            assert engine.start() == 0
            second = library.redsocks_engine_create()
            try:
                assert library.redsocks_engine_start(second, ctypes.byref(engine.options)) == -1
            finally:
                library.redsocks_engine_destroy(second)
            assert engine.stop() == 0


def test_hash_vectors(library):
    out = ctypes.create_string_buffer(256)
    assert library.redsocks_engine_hashes(b"User", b"Domain", b"Password", out, len(out)) == 0
    assert b"PassLM E52CAC67419A9A224A3B108F3FA6CB6D" in out.value
    assert b"PassNT A4F49C406510BDCAB6824EE7C30FD852" in out.value
    # cntlm canonicalizes both user and domain to uppercase.
    assert b"PassNTLMv2 F38EFEA48ADA6AFAA95AE44669E5634B" in out.value


@pytest.mark.parametrize("host", ["proxy.test", "127.0.0.1"])
@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_upstream_tls_sni_ip_and_buffered_payload(library, tmp_path, certificates, host, version):
    port = unused_port(); payload = hello("target.test") + bytes(range(256))*1024
    def upstream(conn, i):
        line, h = headers(conn)
        assert line == f"CONNECT target.test:{port} HTTP/1.0"
        assert h["proxy-authorization"] == "Basic "+base64.b64encode(b"u:p").decode()
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        assert receive_exact(conn, len(payload)) == payload
        conn.sendall(b"echo:"+payload)
    context = tls_context(certificates)
    context.minimum_version = context.maximum_version = version
    with Server(upstream, context) as server:
        with Engine(library, tmp_path, config(port, server.port, tls=True, host=host,
                    extra='login = "u"; password = "p";'), trust=(certificates / "ca.pem").read_bytes()):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(payload)
                assert receive_exact(client, len(payload)+5) == b"echo:"+payload
        # TLS 1.3 can send a second ClientHello after HelloRetryRequest.
        # Every ClientHello must retain the same DNS SNI (or omit IP SNI).
        assert 1 <= len(server.sni) <= (2 if version == ssl.TLSVersion.TLSv1_3 else 1)
        assert all(name == ("proxy.test" if host == "proxy.test" else None) for name in server.sni)


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
@pytest.mark.parametrize("cntlm", [False, True])
def test_tls_close_notify_drains_buffered_response(library, tmp_path, certificates, version, cntlm):
    port = unused_port()
    request = hello("target.test")
    response = bytes(range(256)) * 1024 + b"final-byte"
    ready, release = threading.Event(), threading.Event()
    def upstream(conn, i):
        if cntlm:
            ntlm_step(conn, "NTLMv2")
        else:
            headers(conn)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        assert receive_exact(conn, len(request)) == request
        ready.set()
        assert release.wait(3)
        conn.sendall(response)
        # Send an authenticated EOF while the local client is backpressured.
        conn.unwrap().close()
    context = tls_context(certificates)
    context.minimum_version = context.maximum_version = version
    with Server(upstream, context) as server:
        with Engine(library, tmp_path, config(port, server.port, tls=True, cntlm=cntlm),
                    credentials(server.port) if cntlm else None,
                    trust=(certificates / "ca.pem").read_bytes()) as engine:
            with socket.socket() as client:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                client.settimeout(5)
                client.connect(("127.0.0.1", port))
                client.sendall(request)
                client.shutdown(socket.SHUT_WR)
                assert ready.wait(3)
                # Constrain the accepted engine socket as well as the reader,
                # so the response cannot drain into a large kernel send queue.
                for name in os.listdir('/proc/self/fd'):
                    try:
                        with socket.fromfd(int(name), socket.AF_INET, socket.SOCK_STREAM) as accepted:
                            if (accepted.getsockname() == ('127.0.0.1', port) and
                                    accepted.getpeername() == client.getsockname()):
                                accepted.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                                break
                    except OSError:
                        pass
                else:
                    pytest.fail('engine client socket not found')
                release.set()
                time.sleep(.1)
                assert receive_exact(client, len(response)) == response
                assert client.recv(1) == b""
            began = time.monotonic()
            assert engine.stop() == 0
            assert time.monotonic() - began < 1.5


@pytest.mark.parametrize("failure", ["wrong", "expired", "untrusted"])
def test_reject_invalid_tls_before_proxy_credentials(library, tmp_path, certificates, failure):
    port = unused_port()
    def forbidden(conn, i):
        pytest.fail("Proxy request escaped failed TLS verification")
    with Server(forbidden, tls_context(certificates, failure if failure != "untrusted" else "valid"), expect_tls_error=True) as server:
        trust = (certificates / "ca.pem").read_bytes() if failure != "untrusted" else None
        with Engine(library, tmp_path, config(port, server.port, tls=True, extra='login = "private"; password = "private";'), trust=trust) as engine:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(hello("target.test"))
                assert client.recv(1) == b""
            assert "TLS" in engine.diagnostic()


def type2():
    info = struct.pack("<HH", 2, 12) + "Domain".encode("utf-16le") + bytes(4)
    return b"NTLMSSP\0" + struct.pack("<I", 2) + bytes(8) + struct.pack("<I", 0x00888201) + b"12345678" + bytes(8) + struct.pack("<HHI", len(info), len(info), 48) + info


def ntlm_step(conn, mode, *, chunked=False):
    first, h = headers(conn)
    msg = base64.b64decode(h["proxy-authorization"].split()[1])
    assert msg[:12] == b"NTLMSSP\0\x01\0\0\0"
    challenge = base64.b64encode(type2())
    framing = b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trailer: yes\r\n\r\n" if chunked else b"Content-Length: 3\r\n\r\nabc"
    conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM "+challenge+b"\r\n"+framing)
    line, h = headers(conn)
    response = base64.b64decode(h["proxy-authorization"].split()[1])
    assert response[:12] == b"NTLMSSP\0\x03\0\0\0"
    def field(offset):
        length, allocated, start = struct.unpack_from("<HHI", response, offset)
        assert length == allocated and start+length <= len(response)
        return response[start:start+length]
    lm, nt = field(12), field(20)
    assert len(lm) == (24 if mode in ("LM", "NTLM", "NTLM2SR", "NTLMv2") else 0)
    assert len(nt) == (0 if mode == "LM" else (24 if mode != "NTLMv2" else len(nt)))
    if mode == "NTLMv2":
        key = bytes.fromhex("F38EFEA48ADA6AFAA95AE44669E5634B")
        assert len(nt) > 24
        assert hmac.new(key, b"12345678"+nt[16:], hashlib.md5).digest() == nt[:16]
    return first, line, h


@pytest.mark.parametrize("mode", ["LM", "NT", "NTLM", "NTLM2SR", "NTLMv2"])
@pytest.mark.parametrize("tls", [False, True])
def test_cntlm_dialects_single_upstream_connection(library, tmp_path, certificates, mode, tls):
    port = unused_port(); payload = hello("target.test") + bytes(range(256))*128
    def upstream(conn, i):
        first, final, h = ntlm_step(conn, mode, chunked=True)
        assert first == final == f"CONNECT target.test:{port} HTTP/1.1"
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        assert receive_exact(conn, len(payload)) == payload
        conn.sendall(b"echo:"+payload)
    with Server(upstream, tls_context(certificates) if tls else None) as server:
        with Engine(library, tmp_path, config(port, server.port, tls=tls, cntlm=True),
                    credentials(server.port, mode), trust=(certificates / "ca.pem").read_bytes() if tls else None):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(payload)
                assert receive_exact(client, len(payload)+5) == b"echo:"+payload


def test_cntlm_http_post_not_replayed_and_header(library, tmp_path):
    port = unused_port(); body = bytes(range(256))*32
    def upstream(conn, i):
        first, final, h = ntlm_step(conn, "NTLMv2")
        assert first == "OPTIONS http://target.test/upload HTTP/1.1"
        assert final == "POST http://target.test/upload HTTP/1.1"
        assert h["x-engine-test"] == "custom"
        assert receive_exact(conn, len(body)) == body
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        assert conn.recv(1) == b""
    with Server(upstream) as server:
        with Engine(library, tmp_path, config(port, server.port, cntlm=True, relay="http-relay"),
                    credentials(server.port, extra="Header X-Engine-Test: custom")):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(f"POST /upload HTTP/1.1\r\nHost: target.test\r\nContent-Length: {len(body)}\r\n\r\n".encode()+body)
                line, h = headers(client)
                assert "200" in line and receive_exact(client, 2) == b"ok"


@pytest.mark.parametrize("cntlm", [False, True])
def test_stop_during_pending_tls_handshake(library, tmp_path, cntlm):
    port = unused_port(); accepted = threading.Event(); release = threading.Event()
    def upstream(conn, i):
        accepted.set(); release.wait(4)
    with Server(upstream) as server:
        with Engine(library, tmp_path, config(port, server.port, tls=True, cntlm=cntlm),
                    credentials(server.port) if cntlm else None) as engine:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(hello("target.test"))
                assert accepted.wait(3)
                began = time.monotonic()
                assert engine.stop() == 0
                assert time.monotonic()-began < 1.5
                release.set()


@pytest.mark.parametrize("tls", [False, True])
def test_cntlm_closed_407_restarts_type1(library, tmp_path, certificates, tls):
    port = unused_port(); payload = hello("target.test")
    def upstream(conn, attempt):
        if attempt == 0:
            _, h = headers(conn)
            assert base64.b64decode(h["proxy-authorization"].split()[1])[8:12] == struct.pack("<I", 1)
            conn.sendall(b"HTTP/1.1 407 Required\r\nProxy-Authenticate: NTLM " + base64.b64encode(type2()) +
                         b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        ntlm_step(conn, "NTLMv2")
        conn.sendall(b"HTTP/1.1 200 Connected\r\n\r\n")
        assert receive_exact(conn, len(payload)) == payload
        conn.sendall(b"ok")
    with Server(upstream, tls_context(certificates) if tls else None, connections=2) as server:
        with Engine(library, tmp_path, config(port, server.port, tls=tls, cntlm=True), credentials(server.port),
                    trust=(certificates / "ca.pem").read_bytes() if tls else None):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(payload)
                assert receive_exact(client, 2) == b"ok"


@pytest.mark.parametrize("invalid", ["signature", "offset", "av_length"])
def test_cntlm_rejects_malformed_type2(library, tmp_path, invalid):
    port = unused_port(); challenge = bytearray(type2())
    if invalid == "signature": challenge[0] = ord("X")
    elif invalid == "offset": struct.pack_into("<I", challenge, 44, 0x10030)
    else: struct.pack_into("<H", challenge, 50, 0xffff)
    def upstream(conn, i):
        headers(conn)
        conn.sendall(b"HTTP/1.1 407 Required\r\nProxy-Authenticate: Basic realm=\"other\"\r\n"
                     b"Proxy-Authenticate: NTLM " + base64.b64encode(challenge) + b"\r\nContent-Length: 0\r\n\r\n")
        assert conn.recv(1) == b"", "Type3 was sent for a malformed challenge"
    with Server(upstream) as server:
        with Engine(library, tmp_path, config(port, server.port, cntlm=True), credentials(server.port)):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(hello("target.test"))
                assert client.recv(1) == b""


def test_cntlm_noauth_probe_submits_post_once(library, tmp_path):
    port = unused_port(); body = b"submit-once"
    def upstream(conn, i):
        first, h = headers(conn)
        assert first == "OPTIONS http://target.test/submit HTTP/1.1" and h["content-length"] == "0"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        final, h = headers(conn)
        assert final == "POST http://target.test/submit HTTP/1.1"
        assert "proxy-authorization" not in h
        assert receive_exact(conn, len(body)) == body
        conn.sendall(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    with Server(upstream) as server:
        with Engine(library, tmp_path, config(port, server.port, cntlm=True, relay="http-relay"), credentials(server.port)):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(b"POST /submit HTTP/1.1\r\nHost: target.test\r\nContent-Length: 11\r\n\r\n" + body)
                assert "201" in headers(client)[0]
                assert receive_exact(client, 2) == b"ok"


@pytest.mark.parametrize("reject_cached", [False, True])
@pytest.mark.parametrize("tls", [False, True])
def test_cntlm_cached_stream_and_no_business_replay(library, tmp_path, certificates, tls, reject_cached):
    port = unused_port(); body = b"one-post"
    def upstream(conn, i):
        first, final, h = ntlm_step(conn, "NTLMv2")
        assert first.startswith("OPTIONS ") and final.startswith("GET ")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\nok")
        final, h = headers(conn)
        assert final == "POST http://target.test/second HTTP/1.1"
        assert "proxy-authorization" not in h
        assert receive_exact(conn, len(body)) == body
        code = b"407 Required" if reject_cached else b"200 OK"
        conn.sendall(b"HTTP/1.1 " + code + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        assert conn.recv(1) == b""
    with Server(upstream, tls_context(certificates) if tls else None) as server:
        with Engine(library, tmp_path, config(port, server.port, tls=tls, cntlm=True, relay="http-relay"),
                    credentials(server.port), trust=(certificates / "ca.pem").read_bytes() if tls else None):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(b"GET /first HTTP/1.1\r\nHost: target.test\r\n\r\n")
                assert "200" in headers(client)[0] and receive_exact(client, 2) == b"ok"
                client.shutdown(socket.SHUT_WR)
                assert client.recv(1) == b""  # close follows insertion into the shared cache
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(b"POST /second HTTP/1.1\r\nHost: target.test\r\nContent-Length: 8\r\n\r\n" + body)
                assert ("407" if reject_cached else "200") in headers(client)[0]


@pytest.mark.parametrize("route", ["NoProxy", "Pac"])
def test_cntlm_direct_route_bypasses_tls_parent(library, tmp_path, certificates, route):
    port = unused_port()
    def target(conn, i):
        line, h = headers(conn)
        assert line == "GET /direct HTTP/1.1" and "proxy-authorization" not in h
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    extra = "NoProxy 127.0.0.1"
    if route == "Pac":
        pac = tmp_path / "direct.pac"
        pac.write_text('function FindProxyForURL(url, host) { return "DIRECT"; }')
        extra = "Pac " + str(pac)
    with Server(target) as server:
        with Engine(library, tmp_path, config(port, 9, tls=True, cntlm=True, relay="http-relay"),
                    credentials(9, extra=extra), trust=(certificates / "ca.pem").read_bytes()):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(f"GET /direct HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n\r\n".encode())
                assert "200" in headers(client)[0] and receive_exact(client, 2) == b"ok"


@pytest.mark.parametrize("service", ["Listen", "Tunnel", "SOCKS5Proxy"])
def test_cntlm_extra_services_share_tls_transport(library, tmp_path, certificates, service):
    local = unused_port(); extra_port = unused_port(); payload = b"extra-service" * 1024
    password = "p" * 200
    def upstream(conn, i):
        first, final, h = ntlm_step(conn, "NTLMv2")
        assert first == final == "CONNECT target.test:443 HTTP/1.1"
        conn.sendall(b"HTTP/1.1 200 Connected\r\n\r\n")
        assert receive_exact(conn, len(payload)) == payload
        conn.sendall(payload)
    def fragmented(client, data):
        for part in (data[:1], data[1:]):
            if part: client.sendall(part); time.sleep(0.02)
    specification = f"{service} 127.0.0.1:{extra_port}" + (":target.test:443" if service == "Tunnel" else "")
    if service == "SOCKS5Proxy": specification += "\nSOCKS5User alice:" + password
    with Server(upstream, tls_context(certificates)) as server:
        with Engine(library, tmp_path, config(local, server.port, tls=True, cntlm=True),
                    credentials(server.port, extra=specification), trust=(certificates / "ca.pem").read_bytes()):
            with socket.create_connection(("127.0.0.1", extra_port), timeout=5) as client:
                if service == "Listen":
                    client.sendall(b"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n\r\n")
                    assert "200" in headers(client)[0]
                elif service == "SOCKS5Proxy":
                    fragmented(client, b"\x05\x01\x02")
                    assert receive_exact(client, 2) == b"\x05\x02"
                    fragmented(client, b"\x01\x05alice" + bytes([len(password)]) + password.encode())
                    assert receive_exact(client, 2) == b"\x01\0"
                    fragmented(client, b"\x05\x01\0\x03\x0btarget.test\x01\xbb")
                    assert receive_exact(client, 10)[:2] == b"\x05\0"
                client.sendall(payload)
                assert receive_exact(client, len(payload)) == payload


def test_cntlm_basic_translation(library, tmp_path):
    port = unused_port()
    def upstream(conn, i):
        _, final, h = ntlm_step(conn, "NTLMv2")
        assert final == "GET http://target.test/basic HTTP/1.1"
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    with Server(upstream) as server:
        with Engine(library, tmp_path, config(port, server.port, cntlm=True, relay="http-relay"),
                    credentials(server.port, extra="NTLMToBasic yes")):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                basic = base64.b64encode(b"Domain\\User:Password")
                client.sendall(b"GET /basic HTTP/1.1\r\nHost: target.test\r\nProxy-Authorization: Basic " + basic + b"\r\n\r\n")
                assert "200" in headers(client)[0]


def test_cntlm_acl_and_repeated_configuration_cleanup(library, tmp_path):
    port = unused_port(); extra = unused_port()
    with Engine(library, tmp_path, config(port, 9, cntlm=True),
                credentials(9, extra=f"Listen 127.0.0.1:{extra}\nDeny 127.0.0.1"), start=False) as engine:
        baseline = len(os.listdir("/proc/self/fd"))
        for i in range(12):
            assert engine.start() == 0, engine.diagnostic()
            with socket.create_connection(("127.0.0.1", extra), timeout=5) as client:
                assert client.recv(1) == b""
            assert engine.stop() == 0
        assert len(os.listdir("/proc/self/fd")) <= baseline + 1
