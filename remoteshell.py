#!/usr/bin/env python3
"""
remoteshell - simple password-protected remote shell over HTTP.

Pure standard-library Python 3 (no dependencies), so it runs on virtually
any Linux box that has python3 installed. Launch it directly, passing the
password as a launch parameter. A client sends a POST request carrying the
command to run; the server executes it in a shell and streams the result
back in the response.

Designed to handle arbitrarily long input and output:
  * the request body is streamed to the command's stdin (long input);
  * the command's stdout+stderr are streamed back using HTTP chunked
    transfer encoding (long output), so nothing is buffered fully in
    memory on either side.

Usage:
    sudo ./remoteshell.py --password 's3cr3t'
    sudo ./remoteshell.py --password 's3cr3t' --host 0.0.0.0 --port 433

Client examples (curl):
    # run a command
    curl -sS -X POST http://HOST:433/exec \\
         -H 'X-Auth-Token: s3cr3t' \\
         -H 'X-Command: ls -la /var/log'

    # pipe (large) data to the command's stdin
    curl -sS -X POST http://HOST:433/exec \\
         -H 'X-Auth-Token: s3cr3t' \\
         -H 'X-Command: gzip -c | wc -c' \\
         --data-binary @bigfile.dat

The command's exit status is returned in the HTTP trailer "X-Exit-Code".
"""

import argparse
import hmac
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Read/write block size used for streaming. 64 KiB is a good trade-off.
CHUNK_SIZE = 64 * 1024

# Populated from the launch parameters in main().
PASSWORD = ""
SHELL = "/bin/sh"


class ShellHandler(BaseHTTPRequestHandler):
    # Advertise HTTP/1.1 so chunked transfer encoding is allowed.
    protocol_version = "HTTP/1.1"
    server_version = "remoteshell/1.0"

    # ---- helpers --------------------------------------------------------

    def _authorized(self):
        """Constant-time comparison of the supplied token with the password."""
        token = self.headers.get("X-Auth-Token", "")
        return hmac.compare_digest(token.encode(), PASSWORD.encode())

    def _send_plain(self, code, message):
        body = (message + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _write_chunk(self, data):
        """Write one HTTP chunk."""
        self.wfile.write(b"%X\r\n" % len(data))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")

    # ---- request handling ----------------------------------------------

    def do_GET(self):
        # A tiny health/usage endpoint; no command execution here.
        self._send_plain(
            200,
            "remoteshell is running.\n"
            "POST to /exec with headers 'X-Auth-Token' and 'X-Command'.",
        )

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/exec":
            self._send_plain(404, "Not found. Use POST /exec.")
            return

        if not self._authorized():
            self._send_plain(401, "Unauthorized.")
            return

        command = self.headers.get("X-Command")
        if not command:
            self._send_plain(400, "Missing 'X-Command' header.")
            return

        self.log_message("exec: %s", command)
        self._run_streaming(command)

    def _run_streaming(self, command):
        """Run the command, streaming stdin in and stdout/stderr out."""
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

        # Start the chunked response. We declare a trailer so the client can
        # learn the exit code after the (possibly huge) output has streamed.
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Trailer", "X-Exit-Code")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        # Pump the request body into the command's stdin on a side thread so
        # that reading stdout and writing stdin happen concurrently (avoids
        # deadlock when both pipes fill up with large data).
        feeder = threading.Thread(
            target=self._feed_stdin, args=(proc,), daemon=True
        )
        feeder.start()

        try:
            while True:
                out = proc.stdout.read(CHUNK_SIZE)
                if not out:
                    break
                self._write_chunk(out)
        except (BrokenPipeError, ConnectionResetError):
            # Client went away; tear the command down and stop.
            proc.kill()
            feeder.join(timeout=5)
            return
        finally:
            proc.stdout.close()

        rc = proc.wait()
        feeder.join(timeout=5)

        # Final (zero-length) chunk followed by the trailer and terminator.
        self.wfile.write(b"0\r\n")
        self.wfile.write(b"X-Exit-Code: %d\r\n" % rc)
        self.wfile.write(b"\r\n")

    def _feed_stdin(self, proc):
        """Stream the request body to the command's stdin, then close it."""
        try:
            length = self.headers.get("Content-Length")
            if length is not None:
                remaining = int(length)
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

    # Keep the default access logging (writes to stderr).


def main(argv=None):
    parser = argparse.ArgumentParser(description="Password-protected remote shell over HTTP.")
    parser.add_argument(
        "-p", "--password",
        help="Access password. May also be set via the REMOTESHELL_PASSWORD env var.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0).")
    parser.add_argument("--port", type=int, default=433, help="Listen port (default: 433).")
    parser.add_argument("--shell", default="/bin/sh", help="Shell used to run commands (default: /bin/sh).")
    args = parser.parse_args(argv)

    global PASSWORD, SHELL
    PASSWORD = args.password or os.environ.get("REMOTESHELL_PASSWORD", "")
    SHELL = args.shell

    if not PASSWORD:
        parser.error("a password is required (use --password or REMOTESHELL_PASSWORD)")
    if not shutil.which(SHELL) and not os.path.exists(SHELL):
        parser.error("shell not found: %s" % SHELL)

    server = ThreadingHTTPServer((args.host, args.port), ShellHandler)
    sys.stderr.write(
        "remoteshell listening on %s:%d (shell=%s)\n" % (args.host, args.port, SHELL)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nshutting down\n")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
