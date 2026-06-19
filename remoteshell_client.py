"""
remoteshell_client - embeddable client SDK for remoteshell.

Single-file, pure standard-library Python 3. Drop it next to your agent and
`from remoteshell_client import RemoteShellClient`. No dependencies, no
certificate files: when talking to a TLS server it authenticates by pinning
the certificate's SHA-256 fingerprint (the value the server prints at startup).

Quick start:

    from remoteshell_client import RemoteShellClient

    rs = RemoteShellClient(
        "https://host:433",
        password="s3cr3t",
        fingerprint="sha256:fdf7e1aa...",   # printed by the server
    )

    # one-shot command (captures exit code from the HTTP trailer)
    res = rs.run("uname -a")
    print(res.output.decode(), res.exit_code)

    # interactive session (expect/send style, ideal for agents)
    with rs.open_session() as sh:               # default: a login shell
        sh.read_until("$ ", timeout=10)         # wait for the prompt
        sh.send("ls -la\n")
        print(sh.read_until("$ ", timeout=10).decode())
        sh.send("exit\n")

See AGENT_SPEC.md for the full wire protocol.
"""

import hashlib
import hmac
import json
import socket
import ssl
import time
import urllib.parse

__all__ = ["RemoteShellClient", "Session", "RunResult", "RemoteShellError"]


class RemoteShellError(Exception):
    """Raised on protocol/auth errors returned by the server."""


class RunResult:
    """Result of a one-shot command."""

    __slots__ = ("output", "exit_code")

    def __init__(self, output, exit_code):
        self.output = output          # bytes: merged stdout+stderr
        self.exit_code = exit_code    # int: command exit status (-1 if unknown)

    def __repr__(self):
        return "RunResult(exit_code=%d, %d bytes)" % (self.exit_code, len(self.output))


class _ChunkedStream:
    """Iterator over a chunked response body; collects trailers at the end."""

    def __init__(self, rfile):
        self._rfile = rfile
        self.trailers = {}
        self._done = False

    def __iter__(self):
        return self

    def __next__(self):
        if self._done:
            raise StopIteration
        size_line = self._rfile.readline()
        if not size_line:
            self._done = True
            raise StopIteration
        size_line = size_line.strip()
        if size_line == b"":
            return self.__next__()
        size = int(size_line.split(b";", 1)[0], 16)
        if size == 0:
            while True:
                line = self._rfile.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                key, _, val = line.partition(b":")
                self.trailers[key.strip().lower().decode()] = val.strip().decode()
            self._done = True
            raise StopIteration
        data = b""
        while len(data) < size:
            buf = self._rfile.read(size - len(data))
            if not buf:
                self._done = True
                raise StopIteration
            data += buf
        self._rfile.read(2)  # trailing CRLF
        return data

    @property
    def exit_code(self):
        try:
            return int(self.trailers.get("x-exit-code", "-1"))
        except ValueError:
            return -1


class RemoteShellClient:
    """Client for a remoteshell server."""

    def __init__(self, url, password, fingerprint=None, insecure=False, timeout=30):
        u = urllib.parse.urlparse(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("url must start with http:// or https://")
        self._host = u.hostname
        self._port = u.port or (443 if u.scheme == "https" else 80)
        self._tls = u.scheme == "https"
        self._password = password
        self._insecure = insecure
        self._timeout = timeout
        self._fingerprint = None
        if fingerprint:
            self._fingerprint = (
                fingerprint.lower().replace("sha256:", "").replace(":", "").strip()
            )
        if self._tls:
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # ---- connection / low-level HTTP -----------------------------------

    def _connect(self, timeout=None):
        sock = socket.create_connection(
            (self._host, self._port), timeout=timeout or self._timeout
        )
        if self._tls:
            sock = self._ctx.wrap_socket(sock, server_hostname=self._host)
            der = sock.getpeercert(binary_form=True)
            actual = hashlib.sha256(der).hexdigest()
            if self._fingerprint is not None:
                if not hmac.compare_digest(actual, self._fingerprint):
                    sock.close()
                    raise RemoteShellError(
                        "TLS fingerprint mismatch (expected %s, got %s)"
                        % (self._fingerprint, actual)
                    )
            elif not self._insecure:
                sock.close()
                raise RemoteShellError(
                    "No fingerprint pinned and insecure=False. Server fingerprint "
                    "is sha256:%s -- pass it as fingerprint=..." % actual
                )
        return sock

    def _send(self, sock, method, path, headers, body=b""):
        if isinstance(body, str):
            body = body.encode()
        lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % self._host]
        hdrs = {"X-Auth-Token": self._password, "Content-Length": str(len(body))}
        hdrs.update(headers or {})
        for key, val in hdrs.items():
            lines.append("%s: %s" % (key, val))
        data = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
        sock.sendall(data)

    @staticmethod
    def _read_head(rfile):
        status_line = rfile.readline().decode("latin1").strip()
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 else 0
        headers = {}
        while True:
            line = rfile.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            key, _, val = line.partition(b":")
            headers[key.strip().lower().decode()] = val.strip().decode()
        return status, headers

    def _read_simple(self, rfile):
        """Read a full non-streaming response: (status, headers, body)."""
        status, headers = self._read_head(rfile)
        if headers.get("transfer-encoding", "").lower() == "chunked":
            stream = _ChunkedStream(rfile)
            body = b"".join(stream)
        else:
            length = int(headers.get("content-length", 0) or 0)
            body = rfile.read(length) if length else b""
        return status, headers, body

    # ---- one-shot -------------------------------------------------------

    def run(self, command, stdin=b""):
        """Run a command non-interactively; return a RunResult."""
        if isinstance(stdin, str):
            stdin = stdin.encode()
        sock = self._connect()
        try:
            rfile = sock.makefile("rb")
            self._send(sock, "POST", "/exec", {"X-Command": command}, stdin)
            status, headers = self._read_head(rfile)
            if status != 200:
                raise RemoteShellError("exec failed (%d): %s" % (status, rfile.read().decode(errors="replace").strip()))
            stream = _ChunkedStream(rfile)
            output = b"".join(stream)
            return RunResult(output, stream.exit_code)
        finally:
            sock.close()

    # ---- interactive ----------------------------------------------------

    def open_session(self, command=None, rows=0, cols=0):
        """Create an interactive PTY session; return a Session."""
        sock = self._connect()
        try:
            rfile = sock.makefile("rb")
            headers = {}
            if command:
                headers["X-Command"] = command
            if rows and cols:
                headers["X-Rows"] = str(rows)
                headers["X-Cols"] = str(cols)
            self._send(sock, "POST", "/session", headers)
            status, _, body = self._read_simple(rfile)
            if status != 201:
                raise RemoteShellError("session create failed (%d): %s" % (status, body.decode(errors="replace").strip()))
            sid = json.loads(body)["id"]
        finally:
            sock.close()
        return Session(self, sid)


class Session:
    """An interactive PTY session. Drive it with send()/read()/read_until().

    Output is streamed from the raw socket with per-call timeouts so that
    expect-style waits (read_until) never leave the connection in a bad state.
    """

    def __init__(self, client, session_id):
        self._client = client
        self.id = session_id
        self._out_sock = None
        self._in_sock = None
        self._in_rfile = None
        self._closed = False
        # Incremental chunked-decoder state for the output stream.
        self._raw = bytearray()
        self._eof = False
        self._state = "size"      # size -> data -> ... -> done
        self._chunk_left = 0
        self.trailers = {}

    # -- output side (raw socket + manual chunked decoding) --

    def _fill(self, deadline):
        """Pull more bytes from the socket. Return False on timeout/EOF."""
        timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        self._out_sock.settimeout(timeout)
        try:
            data = self._out_sock.recv(CHUNK := 65536)
        except (socket.timeout, TimeoutError, BlockingIOError,
                ssl.SSLWantReadError):
            return False
        if not data:
            self._eof = True
            return False
        self._raw += data
        return True

    def _ensure_raw(self, n, deadline):
        while len(self._raw) < n:
            if self._eof or not self._fill(deadline):
                return False
        return True

    def _readline_raw(self, deadline):
        while b"\n" not in self._raw:
            if self._eof or not self._fill(deadline):
                return None
        idx = self._raw.index(b"\n")
        line = bytes(self._raw[: idx + 1])
        del self._raw[: idx + 1]
        return line

    def _read_trailers(self, deadline):
        while True:
            line = self._readline_raw(deadline)
            if line is None or line in (b"\r\n", b"\n"):
                break
            key, _, val = line.partition(b":")
            self.trailers[key.strip().lower().decode()] = val.strip().decode()

    def _ensure_output(self):
        if self._out_sock is not None:
            return
        self._out_sock = self._client._connect()
        self._client._send(self._out_sock, "GET", "/session/%s/output" % self.id, {})
        status_line = self._readline_raw(None)
        status = int(status_line.split(b" ")[1]) if status_line else 0
        while True:  # consume response headers
            line = self._readline_raw(None)
            if line is None or line in (b"\r\n", b"\n"):
                break
        if status != 200:
            raise RemoteShellError("cannot open output stream (%d)" % status)

    def _pull(self, deadline):
        """Return some decoded payload bytes, or b'' on timeout / end."""
        self._ensure_output()
        while True:
            if self._state == "done":
                return b""
            if self._state == "size":
                line = self._readline_raw(deadline)
                if line is None:
                    return b""
                line = line.strip()
                if line == b"":
                    continue
                self._chunk_left = int(line.split(b";", 1)[0], 16)
                if self._chunk_left == 0:
                    self._read_trailers(deadline)
                    self._state = "done"
                    return b""
                self._state = "data"
            if self._state == "data":
                if not self._ensure_raw(1, deadline):
                    return b""
                take = min(self._chunk_left, len(self._raw))
                data = bytes(self._raw[:take])
                del self._raw[:take]
                self._chunk_left -= take
                if self._chunk_left == 0:
                    if self._ensure_raw(2, deadline):
                        del self._raw[:2]  # trailing CRLF
                    self._state = "size"
                return data

    def read(self, timeout=None):
        """Return the next available output bytes, or b'' at timeout/end."""
        deadline = None if timeout is None else time.monotonic() + timeout
        return self._pull(deadline)

    def read_until(self, pattern, timeout=None):
        """Read output until `pattern` (str/bytes) appears or timeout elapses.

        Returns everything read so far (bytes). Useful for waiting on prompts.
        """
        if isinstance(pattern, str):
            pattern = pattern.encode()
        deadline = None if timeout is None else time.monotonic() + timeout
        out = bytearray()
        while True:
            chunk = self._pull(deadline)
            if not chunk:
                break
            out += chunk
            if pattern in out:
                break
        return bytes(out)

    # -- input side --
    def _ensure_input(self):
        if self._in_sock is None:
            self._in_sock = self._client._connect()
            self._in_rfile = self._in_sock.makefile("rb")

    def send(self, data):
        """Write bytes/str to the terminal (include '\\n' for Enter)."""
        if isinstance(data, str):
            data = data.encode()
        self._ensure_input()
        self._client._send(self._in_sock, "POST", "/session/%s/input" % self.id, {}, data)
        status, _, _ = self._client._read_simple(self._in_rfile)
        if status == 404:
            raise RemoteShellError("session %s no longer exists" % self.id)

    def resize(self, rows, cols):
        sock = self._client._connect()
        try:
            rfile = sock.makefile("rb")
            self._client._send(sock, "POST", "/session/%s/resize" % self.id,
                               {"X-Rows": str(rows), "X-Cols": str(cols)})
            self._client._read_simple(rfile)
        finally:
            sock.close()

    @property
    def exit_code(self):
        """Command exit status, available once the output stream has ended."""
        try:
            return int(self.trailers.get("x-exit-code", "-1"))
        except ValueError:
            return -1

    def close(self):
        """Terminate the session and release its connections."""
        if self._closed:
            return
        self._closed = True
        try:
            sock = self._client._connect()
            try:
                rfile = sock.makefile("rb")
                self._client._send(sock, "DELETE", "/session/%s" % self.id, {})
                self._client._read_simple(rfile)
            finally:
                sock.close()
        except OSError:
            pass
        for s in (self._out_sock, self._in_sock):
            try:
                if s:
                    s.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
