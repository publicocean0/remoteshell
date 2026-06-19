#!/usr/bin/env python3
"""
rsh-client - client for remoteshell.

Pure standard-library Python 3, so the client needs nothing extra: no
certificate files, no CA, no pip packages. When talking to a TLS server it
verifies the server by *pinning* the certificate's SHA-256 fingerprint
(Trust On First Use): the server prints its fingerprint at startup, you pass
that single string with --fingerprint, and the client refuses to talk to any
server presenting a different certificate.

Modes:
    rsh-client.py URL exec  COMMAND...     # run one command, stream output
    rsh-client.py URL shell [COMMAND]      # interactive session (PTY)

Examples:
    rsh-client.py https://host:433 --fingerprint sha256:ab12... exec 'ls -la /'
    echo data | rsh-client.py https://host:433 -f sha256:ab12... exec 'wc -c'
    rsh-client.py https://host:433 -f sha256:ab12... shell

The password comes from --password/-p or the REMOTESHELL_PASSWORD env var.
"""

import argparse
import fcntl
import hashlib
import hmac
import http.client
import json
import os
import select
import signal
import ssl
import struct
import sys
import termios
import threading
import tty
import urllib.parse

CHUNK_SIZE = 64 * 1024


def get_winsize(fd=0):
    try:
        packed = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols, _, _ = struct.unpack("HHHH", packed)
        return rows, cols
    except OSError:
        return 24, 80


def build_factory(url, fingerprint, insecure):
    """Return a function that creates a fresh (verified) HTTP(S) connection."""
    u = urllib.parse.urlparse(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)

    if u.scheme != "https":
        def factory(timeout=30):
            return http.client.HTTPConnection(host, port, timeout=timeout)
        return factory

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    want = None
    if fingerprint:
        want = fingerprint.lower().replace("sha256:", "").replace(":", "").strip()

    def factory(timeout=30):
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        actual = hashlib.sha256(der).hexdigest()
        if want is not None:
            if not hmac.compare_digest(actual, want):
                conn.close()
                raise SystemExit(
                    "TLS fingerprint mismatch -- refusing to connect.\n"
                    "  expected: %s\n  got:      %s" % (want, actual)
                )
        elif not insecure:
            conn.close()
            raise SystemExit(
                "No --fingerprint given and --insecure not set, refusing.\n"
                "The server printed its fingerprint at startup. It is:\n"
                "  sha256:%s\n"
                "Re-run with --fingerprint sha256:%s" % (actual, actual)
            )
        return conn

    return factory


def cmd_exec(args, factory, password):
    command = " ".join(args.command)
    body = b"" if os.isatty(0) else sys.stdin.buffer.read()
    conn = factory()
    conn.request(
        "POST", "/exec",
        body=body,
        headers={
            "X-Auth-Token": password,
            "X-Command": command,
            "Content-Length": str(len(body)),
        },
    )
    resp = conn.getresponse()
    if resp.status != 200:
        sys.stderr.write(resp.read().decode(errors="replace"))
        return 1
    while True:
        chunk = resp.read(CHUNK_SIZE)
        if not chunk:
            break
        os.write(1, chunk)
    conn.close()
    return 0


def cmd_shell(args, factory, password):
    headers = {"X-Auth-Token": password}
    if args.command:
        headers["X-Command"] = " ".join(args.command)
    in_tty = os.isatty(0)
    if in_tty:
        rows, cols = get_winsize()
        headers["X-Rows"] = str(rows)
        headers["X-Cols"] = str(cols)

    # Create the session.
    conn = factory()
    conn.request("POST", "/session", headers=headers)
    resp = conn.getresponse()
    if resp.status != 201:
        sys.stderr.write(resp.read().decode(errors="replace"))
        return 1
    sid = json.loads(resp.read())["id"]
    conn.close()

    auth = {"X-Auth-Token": password}
    stop = threading.Event()

    # Output: its own long-lived connection (no read timeout).
    out_conn = factory(timeout=10)
    out_conn.sock.settimeout(None)
    out_conn.request("GET", "/session/%s/output" % sid, headers=auth)
    out_resp = out_conn.getresponse()

    def pump_output():
        try:
            while True:
                chunk = out_resp.read(CHUNK_SIZE)
                if not chunk:
                    break
                os.write(1, chunk)
        except OSError:
            pass
        finally:
            stop.set()

    threading.Thread(target=pump_output, daemon=True).start()

    # Input: its own (reused) connection.
    in_conn = factory()

    def send_input(data):
        in_conn.request(
            "POST", "/session/%s/input" % sid,
            body=data,
            headers={"X-Auth-Token": password, "Content-Length": str(len(data))},
        )
        in_conn.getresponse().read()

    fd = sys.stdin.fileno()
    old_attr = None
    if in_tty:
        old_attr = termios.tcgetattr(fd)
        tty.setraw(fd)

        def on_winch(*_):
            rows, cols = get_winsize()
            try:
                rc = factory()
                rc.request(
                    "POST", "/session/%s/resize" % sid,
                    headers={"X-Auth-Token": password, "X-Rows": str(rows), "X-Cols": str(cols)},
                )
                rc.getresponse().read()
                rc.close()
            except Exception:
                pass

        signal.signal(signal.SIGWINCH, on_winch)

    input_done = False
    try:
        while not stop.is_set():
            if input_done:
                stop.wait(0.2)
                continue
            ready, _, _ = select.select([fd], [], [], 0.2)
            if fd in ready:
                data = os.read(fd, CHUNK_SIZE)
                if not data:
                    input_done = True  # stdin EOF; keep draining output
                    continue
                send_input(data)
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        if old_attr is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attr)
        for c in (out_conn, in_conn):
            try:
                c.close()
            except OSError:
                pass
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Client for remoteshell.")
    parser.add_argument("url", help="Server base URL, e.g. https://host:433")
    parser.add_argument("-p", "--password", help="Password (or REMOTESHELL_PASSWORD env var).")
    parser.add_argument("-f", "--fingerprint", help="Expected server cert SHA-256 (pinning).")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip TLS fingerprint check.")

    sub = parser.add_subparsers(dest="mode", required=True)
    p_exec = sub.add_parser("exec", help="Run one command and stream its output.")
    p_exec.add_argument("command", nargs="+")
    p_shell = sub.add_parser("shell", help="Open an interactive PTY session.")
    p_shell.add_argument("command", nargs="*")

    args = parser.parse_args(argv)
    password = args.password or os.environ.get("REMOTESHELL_PASSWORD", "")
    if not password:
        parser.error("a password is required (use --password or REMOTESHELL_PASSWORD)")

    factory = build_factory(args.url, args.fingerprint, args.insecure)
    if args.mode == "exec":
        return cmd_exec(args, factory, password)
    return cmd_shell(args, factory, password)


if __name__ == "__main__":
    sys.exit(main())
