#!/usr/bin/env python3
"""
remoteshell - simple password-protected remote shell over HTTP.

Pure standard-library Python 3 (no dependencies), so it runs on virtually
any Linux box that has python3 installed. Launch it directly, passing the
password as a launch parameter.

Two modes are supported:

1. One-shot commands  -- POST /exec
   The client sends a command; the server runs it in a shell and streams
   stdout+stderr back. The request body is streamed to the command's stdin,
   so arbitrarily long input/output are handled without buffering.

2. Interactive sessions (PTY)  -- /session endpoints
   The server allocates a real pseudo-terminal, so programs that need a TTY
   and/or user interaction (bash prompts, vi, top, sudo, python REPL, ...)
   work. The session is driven full-duplex over separate HTTP connections:
     POST   /session                 -> create a session, returns its id
     GET    /session/<id>/output     -> stream the terminal output (chunked)
     POST   /session/<id>/input      -> send keystrokes to the terminal
     DELETE /session/<id>            -> terminate the session

Usage:
    sudo ./remoteshell.py --password 's3cr3t'
    sudo ./remoteshell.py --password 's3cr3t' --host 0.0.0.0 --port 433

See README.md for client (curl) examples. All endpoints require the
'X-Auth-Token' header to match the launch password.
"""

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import pty
import shutil
import ssl
import struct
import subprocess
import sys
import termios
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Read/write block size used for streaming. 64 KiB is a good trade-off.
CHUNK_SIZE = 64 * 1024

# Populated from the launch parameters in main().
PASSWORD = ""
SHELL = "/bin/sh"

# Live interactive sessions, keyed by id.
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()


def _pty_preexec():
    """Run in the child before exec: make the pty the controlling terminal."""
    os.setsid()
    try:
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError:
        pass


class Session:
    """An interactive command running behind a pseudo-terminal."""

    def __init__(self, command, rows, cols):
        self.id = os.urandom(8).hex()
        self.master_fd, slave_fd = pty.openpty()
        if rows and cols:
            self.set_winsize(rows, cols)
        # No command -> launch an interactive shell.
        argv = [SHELL, "-c", command] if command else [SHELL, "-i"]
        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=_pty_preexec,
                close_fds=True,
            )
        finally:
            os.close(slave_fd)
        self.write_lock = threading.Lock()

    def set_winsize(self, rows, cols):
        fcntl.ioctl(
            self.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0)
        )

    def write(self, data):
        with self.write_lock:
            os.write(self.master_fd, data)

    def close(self):
        try:
            self.proc.kill()
        except OSError:
            pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass


def _register(session):
    with SESSIONS_LOCK:
        SESSIONS[session.id] = session


def _lookup(session_id):
    with SESSIONS_LOCK:
        return SESSIONS.get(session_id)


def _unregister(session_id):
    with SESSIONS_LOCK:
        SESSIONS.pop(session_id, None)


class ShellHandler(BaseHTTPRequestHandler):
    # Advertise HTTP/1.1 so chunked transfer encoding is allowed.
    protocol_version = "HTTP/1.1"
    server_version = "remoteshell/1.0"

    # ---- helpers --------------------------------------------------------

    def _authorized(self):
        """Constant-time comparison of the supplied token with the password."""
        token = self.headers.get("X-Auth-Token", "")
        return hmac.compare_digest(token.encode(), PASSWORD.encode())

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _send_plain(self, code, message):
        body = (message + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, code, obj):
        body = (json.dumps(obj) + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _begin_chunked(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Trailer", "X-Exit-Code")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _write_chunk(self, data):
        self.wfile.write(b"%X\r\n" % len(data))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")

    def _end_chunked(self, exit_code):
        self.wfile.write(b"0\r\n")
        self.wfile.write(b"X-Exit-Code: %d\r\n" % exit_code)
        self.wfile.write(b"\r\n")

    # ---- routing --------------------------------------------------------

    def do_GET(self):
        path = self._path()
        if path == "/":
            self._send_plain(
                200,
                "remoteshell is running.\n"
                "POST /exec (one-shot) or use /session endpoints (interactive).",
            )
            return
        if not self._authorized():
            self._send_plain(401, "Unauthorized.")
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "session" and parts[2] == "output":
            self._session_output(parts[1])
            return
        self._send_plain(404, "Not found.")

    def do_POST(self):
        if not self._authorized():
            self._send_plain(401, "Unauthorized.")
            return
        path = self._path()
        if path == "/exec":
            self._exec_oneshot()
            return
        if path == "/session":
            self._session_create()
            return
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "session" and parts[2] == "input":
            self._session_input(parts[1])
            return
        if len(parts) == 3 and parts[0] == "session" and parts[2] == "resize":
            self._session_resize(parts[1])
            return
        self._send_plain(404, "Not found.")

    def do_DELETE(self):
        if not self._authorized():
            self._send_plain(401, "Unauthorized.")
            return
        parts = self._path().strip("/").split("/")
        if len(parts) == 2 and parts[0] == "session":
            sess = _lookup(parts[1])
            if sess is None:
                self._send_plain(404, "No such session.")
                return
            sess.close()
            _unregister(sess.id)
            self._send_plain(200, "Session terminated.")
            return
        self._send_plain(404, "Not found.")

    # ---- one-shot mode (POST /exec) ------------------------------------

    def _exec_oneshot(self):
        command = self.headers.get("X-Command")
        if not command:
            self._send_plain(400, "Missing 'X-Command' header.")
            return
        self.log_message("exec: %s", command)
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                executable=SHELL,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # merge stderr into the stream
                bufsize=0,
            )
        except OSError as exc:
            self._send_plain(500, "Failed to start command: %s" % exc)
            return

        self._begin_chunked()

        # Pump the request body into stdin on a side thread so reading stdout
        # and writing stdin run concurrently (avoids deadlock on large data).
        feeder = threading.Thread(target=self._feed_stdin, args=(proc,), daemon=True)
        feeder.start()

        try:
            while True:
                out = proc.stdout.read(CHUNK_SIZE)
                if not out:
                    break
                self._write_chunk(out)
        except (BrokenPipeError, ConnectionResetError):
            proc.kill()
            feeder.join(timeout=5)
            return
        finally:
            proc.stdout.close()

        rc = proc.wait()
        feeder.join(timeout=5)
        self._end_chunked(rc)

    def _feed_stdin(self, proc):
        """Stream the request body to the command's stdin, then close it."""
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                proc.stdin.write(chunk)
        except (BrokenPipeError, ConnectionResetError, ValueError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    # ---- interactive mode (/session) -----------------------------------

    def _session_create(self):
        command = self.headers.get("X-Command")  # optional; default = shell
        try:
            rows = int(self.headers.get("X-Rows", 0) or 0)
            cols = int(self.headers.get("X-Cols", 0) or 0)
        except ValueError:
            rows = cols = 0
        try:
            sess = Session(command, rows, cols)
        except OSError as exc:
            self._send_plain(500, "Failed to create session: %s" % exc)
            return
        _register(sess)
        self.log_message("session %s created: %s", sess.id, command or SHELL)
        self._send_json(
            201,
            {
                "id": sess.id,
                "output": "/session/%s/output" % sess.id,
                "input": "/session/%s/input" % sess.id,
            },
        )

    def _session_input(self, session_id):
        sess = _lookup(session_id)
        if sess is None:
            self._send_plain(404, "No such session.")
            return
        data = self._read_body()
        try:
            sess.write(data)
        except OSError as exc:
            self._send_plain(500, "Write failed: %s" % exc)
            return
        self._send_plain(200, "ok")

    def _session_resize(self, session_id):
        sess = _lookup(session_id)
        if sess is None:
            self._send_plain(404, "No such session.")
            return
        try:
            rows = int(self.headers.get("X-Rows", 0) or 0)
            cols = int(self.headers.get("X-Cols", 0) or 0)
            if rows and cols:
                sess.set_winsize(rows, cols)
        except (ValueError, OSError) as exc:
            self._send_plain(400, "Resize failed: %s" % exc)
            return
        self._send_plain(200, "ok")

    def _session_output(self, session_id):
        sess = _lookup(session_id)
        if sess is None:
            self._send_plain(404, "No such session.")
            return
        self._begin_chunked()
        try:
            while True:
                try:
                    data = os.read(sess.master_fd, CHUNK_SIZE)
                except OSError:
                    # EIO is raised on Linux once the child has exited.
                    break
                if not data:
                    break
                self._write_chunk(data)
        except (BrokenPipeError, ConnectionResetError):
            return

        rc = sess.proc.poll()
        if rc is None:
            try:
                rc = sess.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                rc = -1
        self._end_chunked(rc if rc is not None else -1)
        sess.close()
        _unregister(sess.id)

    # Keep the default access logging (writes to stderr).


def cert_fingerprint(cert_path):
    """Return the SHA-256 fingerprint (hex) of a PEM certificate."""
    with open(cert_path) as fh:
        der = ssl.PEM_cert_to_DER_cert(fh.read())
    return hashlib.sha256(der).hexdigest()


def ensure_self_signed(cert_path, key_path, days):
    """Generate a self-signed cert/key with openssl if they don't exist."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    if not shutil.which("openssl"):
        raise SystemExit("openssl not found: provide --cert/--key or install openssl")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", str(days), "-nodes", "-subj", "/CN=remoteshell",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.chmod(key_path, 0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Password-protected remote shell over HTTP.")
    parser.add_argument(
        "-p", "--password",
        help="Access password. May also be set via the REMOTESHELL_PASSWORD env var.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0).")
    parser.add_argument("--port", type=int, default=433, help="Listen port (default: 433).")
    parser.add_argument("--shell", default="/bin/sh", help="Shell used to run commands (default: /bin/sh).")
    parser.add_argument("--tls", action="store_true", help="Serve over HTTPS (TLS).")
    parser.add_argument("--cert", default="remoteshell.crt", help="TLS certificate path (default: remoteshell.crt).")
    parser.add_argument("--key", default="remoteshell.key", help="TLS private key path (default: remoteshell.key).")
    parser.add_argument("--cert-days", type=int, default=365, help="Validity of an auto-generated cert (default: 365).")
    args = parser.parse_args(argv)

    global PASSWORD, SHELL
    PASSWORD = args.password or os.environ.get("REMOTESHELL_PASSWORD", "")
    SHELL = args.shell

    if not PASSWORD:
        parser.error("a password is required (use --password or REMOTESHELL_PASSWORD)")
    if not shutil.which(SHELL) and not os.path.exists(SHELL):
        parser.error("shell not found: %s" % SHELL)

    server = ThreadingHTTPServer((args.host, args.port), ShellHandler)

    scheme = "http"
    if args.tls:
        ensure_self_signed(args.cert, args.key, args.cert_days)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
        sys.stderr.write(
            "TLS enabled. Pin this fingerprint on the client (--fingerprint):\n"
            "  sha256:%s\n" % cert_fingerprint(args.cert)
        )

    sys.stderr.write(
        "remoteshell listening on %s://%s:%d (shell=%s)\n"
        % (scheme, args.host, args.port, SHELL)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
