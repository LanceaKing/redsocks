"""Unprivileged, loopback-only CONNECT regression tests for Linux.

The generic redirector preserves the local listening port as the original
destination. A mock upstream checks the authority, authentication, and bytes.
Collected with the upstream tests by pytest; no external proxy or credentials
are required.
"""
import base64
import hashlib
import os
from pathlib import Path
import queue
import re
import socket
import struct
import subprocess
import tempfile
import threading
import time

import pytest


def u16(n):
    return struct.pack("!H", n)


def extension(kind, data):
    return u16(kind) + u16(len(data)) + data


def hello(name="www.temu.com", fragment=16384, padding=0):
    ext = extension(0xAAAA, b"GREASE")
    if padding:
        ext += extension(21, bytes(padding))
    if name is not None:
        name = name.encode("ascii")
        names = b"\0" + u16(len(name)) + name
        ext += extension(0, u16(len(names)) + names)
    ext += extension(43, b"\x02\x03\x04")
    body = b"\x03\x03" + bytes(range(32)) + b"\0\0\x02\x13\x01\x01\0" + u16(len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"".join(b"\x16\x03\x01" + u16(len(hs[i:i + fragment])) + hs[i:i + fragment]
                    for i in range(0, len(hs), fragment))


def unused_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def receive_headers(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        part = conn.recv(4096)
        if not part:
            raise AssertionError("EOF before CONNECT headers")
        data += part
        if len(data) > 65536:
            raise AssertionError("oversized CONNECT request")
    headers, rest = data.split(b"\r\n\r\n", 1)
    assert rest == b"", "TLS payload leaked with CONNECT headers"
    lines = headers.decode("ascii").split("\r\n")
    method, authority, version = lines[0].split(" ")
    assert method == "CONNECT" and version == "HTTP/1.0"
    return authority, dict(line.split(": ", 1) for line in lines[1:])


def receive_exact(conn, size):
    result = bytearray()
    while len(result) < size:
        chunk = conn.recv(min(size - len(result), 65536))
        if not chunk:
            raise AssertionError(f"premature EOF: {len(result)}/{size} bytes")
        result.extend(chunk)
    return bytes(result)


def quiet(conn):
    old = conn.gettimeout()
    conn.settimeout(0.035)
    try:
        data = conn.recv(1)
    except socket.timeout:
        pass
    else:
        assert not data, "TLS payload sent before complete upstream 2xx headers"
    finally:
        conn.settimeout(old)


class MockProxy:
    def __init__(self, handler):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(4)
        self.port = self.socket.getsockname()[1]
        self.errors = queue.Queue()
        self.thread = threading.Thread(target=self.run, args=(handler,), daemon=True)

    def run(self, handler):
        try:
            handler(self)
        except BaseException as error:
            self.errors.put(error)

    def accept(self):
        conn, _ = self.socket.accept()
        conn.settimeout(4)
        return conn

    def finish(self):
        self.thread.join(6)
        assert not self.thread.is_alive(), "mock upstream did not finish"
        self.socket.close()
        if not self.errors.empty():
            raise self.errors.get()


def run_case(binary, splice, *, name="www.temu.com", wire=None, fragment=16384,
             bytewise=False, challenge=None, timeout=False, eof=False,
             status=200, forward_error=False, half_close=False, reason=None):
    port = unused_port()
    authority = f"{name if name else '127.0.0.1'}:{port}"
    if reason:
        authority = f"127.0.0.1:{port}"
    wire = hello(name, fragment) if wire is None else wire
    # More than a pump buffer, with distinguishable bytes to catch duplicate
    # or lost buffered ClientHello and subsequent application data.
    extra = bytes(range(256)) * 384
    payload = wire + extra
    response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\nblocked"
    started = time.monotonic()

    def check_auth(headers, retry):
        value = headers.get("Proxy-Authorization", "")
        if challenge == "Digest" and retry:
            assert value.startswith("Digest ")
            parts = re.findall(r'(\w+)=(?:"([^"]*)"|([^, ]+))', value[7:])
            fields = {key: quoted or plain for key, quoted, plain in parts}
            assert fields["uri"] == authority
            md5 = lambda text: hashlib.md5(text.encode()).hexdigest()
            a1, a2 = md5("test-user:test-realm:test-pass"), md5(f"CONNECT:{authority}")
            expected = md5(f'{a1}:test-nonce:{fields["nc"]}:{fields["cnonce"]}:auth:{a2}')
            assert fields["response"] == expected
        else:
            expected = "Basic " + base64.b64encode(b"test-user:test-pass").decode()
            assert value == expected

    def upstream(mock):
        if eof:
            mock.socket.settimeout(1.3)
            with pytest.raises(socket.timeout):
                mock.socket.accept()
            return
        if challenge:
            with mock.accept() as conn:
                got, headers = receive_headers(conn)
                assert got == authority
                check_auth(headers, False)
                quiet(conn)
                conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
                time.sleep(0.025)
                conn.sendall((f'Proxy-Authenticate: {challenge} realm="test-realm", '
                              'nonce="test-nonce", qop="auth"\r\n').encode())
                quiet(conn)
                conn.sendall(b"Content-Length: 0\r\n\r\n")
        with mock.accept() as conn:
            got, headers = receive_headers(conn)
            assert got == authority
            check_auth(headers, bool(challenge))
            if timeout:
                assert time.monotonic() - started > 0.75
                assert time.monotonic() - started < 2.8
            quiet(conn)
            if status != 200:
                conn.sendall(response)
                quiet(conn)
                return
            conn.sendall(b"HTTP/1.1 200 Connection established\r\nX-Mock: yes\r\n")
            quiet(conn)  # A 2xx status line alone does not open the tunnel.
            conn.sendall(b"\r\nready:")
            got = receive_exact(conn, len(payload))
            assert got == payload
            conn.sendall(b"echo:" + got)
            conn.shutdown(socket.SHUT_WR)
            # A second copy of the sniffed bytes must never arrive.
            assert conn.recv(1) == b""

    mock = MockProxy(upstream)
    with tempfile.TemporaryDirectory(prefix="redsocks-connect-") as tmp:
        tmp = Path(tmp)
        config = tmp / "redsocks.conf"
        config.write_text(f'''base {{
 log_debug = on; log_info = on; log = "file:{tmp / 'redsocks.log'}";
 daemon = off; redirector = generic;
}}
redsocks {{
 local_ip = 127.0.0.1; local_port = {port}; ip = 127.0.0.1; port = {mock.port};
 type = http-connect; login = "test-user"; password = "test-pass";
 splice = {"on" if splice else "off"};
 on_proxy_fail = {"forward_http_err" if forward_error else "close"};
}}
''')
        with (tmp / "stderr").open("w+") as stderr:
            env = dict(os.environ)
            env.setdefault("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
            env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
            process = subprocess.Popen([str(binary), "-c", str(config)], stderr=stderr, env=env)
            mock.thread.start()
            try:
                # No sacrificial connection: it would exercise the sniff timer.
                for _ in range(200):
                    log = tmp / "redsocks.log"
                    if log.exists() and "redsocks started" in log.read_text():
                        break
                    if process.poll() is not None:
                        break
                    time.sleep(0.01)
                assert process.poll() is None, "redsocks exited at startup"
                with socket.create_connection(("127.0.0.1", port), timeout=4) as client:
                    client.settimeout(5)
                    started = time.monotonic()
                    if bytewise:
                        for byte in wire:
                            client.sendall(bytes([byte]))
                            time.sleep(0.001)
                    elif wire:
                        client.sendall(wire)
                    if eof:
                        client.shutdown(socket.SHUT_WR)
                        assert client.recv(1) == b""
                    elif status == 200:
                        if timeout:
                            time.sleep(1.1)
                        client.sendall(extra)
                        if half_close:
                            client.shutdown(socket.SHUT_WR)
                        expected = b"ready:echo:" + payload
                        assert receive_exact(client, len(expected)) == expected
                        assert client.recv(1) == b""
                        if not half_close:
                            client.shutdown(socket.SHUT_WR)
                    else:
                        got = b""
                        while True:
                            try:
                                data = client.recv(4096)
                            except ConnectionResetError:
                                break
                            if not data:
                                break
                            got += data
                        assert got == (response if forward_error else b"")
                mock.finish()
                if reason:
                    assert f"reason={reason}" in (tmp / "redsocks.log").read_text()
            except BaseException:
                if (tmp / "redsocks.log").exists():
                    print((tmp / "redsocks.log").read_text())
                raise
            finally:
                process.terminate()
                process.wait(timeout=5)
                stderr.seek(0)
                diagnostics = stderr.read()
                assert process.returncode == 0, diagnostics
                assert "Sanitizer" not in diagnostics


CASES = {
    "sni_basic": {},
    "tcp_bytewise": {"bytewise": True},
    "tls_records_bytewise": {"fragment": 1},
    "basic_407": {"challenge": "Basic"},
    "digest_407": {"challenge": "Digest"},
    "long_digest_uri": {"name": ".".join(["a" * 63] * 3 + ["b" * 61]), "challenge": "Digest"},
    "no_sni": {"name": None, "reason": "no_sni"},
    "non_tls": {"name": None, "wire": b"server-first protocol", "reason": "non_tls"},
    "invalid_sni": {"wire": hello("bad\r\nInjected:yes"), "reason": "invalid_client_hello"},
    "timeout": {"name": None, "wire": b"", "timeout": True, "reason": "probe_timeout"},
    "partial_timeout": {"name": None, "wire": b"\x16\x03", "timeout": True, "reason": "probe_timeout"},
    "probe_limit": {"wire": hello("limit.example", padding=65445), "reason": "probe_limit"},
    "eof_empty": {"wire": b"", "eof": True},
    "eof_partial": {"wire": b"\x16\x03", "eof": True},
    "half_close": {"half_close": True},
    "reject_close": {"status": 403},
    "reject_forward": {"status": 403, "forward_error": True},
}


@pytest.mark.parametrize('splice', [False, True], ids=['buffer', 'splice'])
@pytest.mark.parametrize('case', CASES)
def test_http_connect(redsocks_binary, splice, case):
    run_case(redsocks_binary, splice, **CASES[case])
