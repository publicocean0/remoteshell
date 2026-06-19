# remoteshell

Simple, password-protected remote shell over HTTP. A single Python 3 script
(standard library only, no dependencies), so it runs on virtually any Linux
machine that has `python3` installed.

A client sends a POST request carrying a command; the server runs it in a
shell and **streams** the result back. Long input and long output are handled
without buffering everything in memory:

- the request body is streamed to the command's **stdin** (long input);
- the command's **stdout + stderr** are streamed back with HTTP chunked
  transfer encoding (long output).

## Run the server

```sh
# port 433 is privileged, so root is required for it
sudo ./remoteshell.py --password 's3cr3t'

# or pick a non-privileged port / pass the password via env var
REMOTESHELL_PASSWORD='s3cr3t' ./remoteshell.py --port 8433
```

Options:

| Option        | Default     | Description                                   |
|---------------|-------------|-----------------------------------------------|
| `--password`  | (required)  | Access password (or `REMOTESHELL_PASSWORD`).  |
| `--host`      | `0.0.0.0`   | Bind address.                                 |
| `--port`      | `433`       | Listen port.                                  |
| `--shell`     | `/bin/sh`   | Shell used to run the command.                |

## Client usage (curl)

Run a command:

```sh
curl -sS -X POST http://HOST:433/exec \
     -H 'X-Auth-Token: s3cr3t' \
     -H 'X-Command: ls -la /var/log'
```

Pipe (large) data to the command's stdin:

```sh
curl -sS -X POST http://HOST:433/exec \
     -H 'X-Auth-Token: s3cr3t' \
     -H 'X-Command: gzip -c | wc -c' \
     --data-binary @bigfile.dat
```

The command's exit status is returned in the HTTP trailer `X-Exit-Code`.

## Interactive sessions (PTY)

For commands that need a terminal and/or live user interaction (a `bash`
prompt, `vi`, `top`, `sudo`, a `python` REPL, ...), use the session
endpoints. The server allocates a real pseudo-terminal and you drive it
full-duplex over two connections: one streams the output, the other sends
keystrokes.

```sh
TOKEN='X-Auth-Token: s3cr3t'

# 1. create a session (no X-Command -> interactive shell). Returns its id.
ID=$(curl -sS -X POST http://HOST:433/session -H "$TOKEN" \
     | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

# 2. in one terminal, stream the live output (keep it open):
curl -N http://HOST:433/session/$ID/output -H "$TOKEN"

# 3. in another terminal, send keystrokes (note the trailing newline = Enter):
printf 'ls -la\n'      | curl -sS -X POST http://HOST:433/session/$ID/input -H "$TOKEN" --data-binary @-
printf 'top\n'         | curl -sS -X POST http://HOST:433/session/$ID/input -H "$TOKEN" --data-binary @-
printf 'q'             | curl -sS -X POST http://HOST:433/session/$ID/input -H "$TOKEN" --data-binary @-
printf '\003'          | curl -sS -X POST http://HOST:433/session/$ID/input -H "$TOKEN" --data-binary @-  # Ctrl-C
printf '\004'          | curl -sS -X POST http://HOST:433/session/$ID/input -H "$TOKEN" --data-binary @-  # Ctrl-D (EOF)

# 4. terminate the session explicitly (also happens when the program exits):
curl -sS -X DELETE http://HOST:433/session/$ID -H "$TOKEN"
```

Optional headers on `POST /session`:

- `X-Command`: run a specific command instead of an interactive shell.
- `X-Rows` / `X-Cols`: initial terminal size (useful for full-screen apps).

Control characters work because the PTY is in cooked mode: sending the byte
`\003` raises `SIGINT` (Ctrl-C), `\004` signals end-of-input (Ctrl-D), etc.

## Protocol

- `GET /` — short status/usage message (no auth).
- `POST /exec` — one-shot command.
  - Header `X-Command`: the shell command line to execute.
  - Body (optional): streamed to the command's standard input.
  - Response: chunked stream of stdout+stderr, exit code in the
    `X-Exit-Code` trailer.
- `POST /session` — create an interactive PTY session; returns JSON
  `{"id", "output", "input"}`.
- `GET /session/<id>/output` — chunked stream of the terminal output;
  ends with the `X-Exit-Code` trailer when the program exits.
- `POST /session/<id>/input` — write the request body to the terminal.
- `DELETE /session/<id>` — terminate the session.

All endpoints except `GET /` require the `X-Auth-Token` header.

## TLS

Pass `--tls` to serve over HTTPS. If you don't supply `--cert`/`--key`, the
server generates a self-signed certificate (with `openssl`) on first start
and prints its **SHA-256 fingerprint**:

```
$ sudo ./remoteshell.py --password 's3cr3t' --tls
TLS enabled. Pin this fingerprint on the client (--fingerprint):
  sha256:fdf7e1aa4b59...231a3a3
remoteshell listening on https://0.0.0.0:433 (shell=/bin/sh)
```

Because the certificate is self-signed there is no CA to trust. Instead of
copying certificate files around, the client **pins that fingerprint**
(Trust On First Use): you just give it the one string the server printed.

## Client (`rsh-client.py`)

A standalone, dependency-free Python 3 client — nothing to install on the
client side, no certificate files. It verifies the server purely by the
pinned fingerprint.

```sh
export REMOTESHELL_PASSWORD='s3cr3t'
FP='sha256:fdf7e1aa4b59...231a3a3'   # printed by the server

# one-shot command
./rsh-client.py https://HOST:433 -f "$FP" exec 'ls -la /'

# pipe data to the command's stdin
echo data | ./rsh-client.py https://HOST:433 -f "$FP" exec 'wc -c'

# fully interactive shell (raw local terminal, forwards Ctrl-C, resizes, ...)
./rsh-client.py https://HOST:433 -f "$FP" shell
```

If you connect without `-f`/`--fingerprint`, the client refuses but prints
the fingerprint it saw, so you can copy it and pin it on the next run. Use
`-k`/`--insecure` to skip the check entirely (not recommended). Plain
`http://` URLs also work (no TLS, no fingerprint).

## Programmatic / agent access

The full wire protocol (TLS pinning handshake, headers, endpoints, streaming,
session lifecycle, status codes, and a recommended client algorithm) is
specified in [`AGENT_SPEC.md`](AGENT_SPEC.md) — enough for an autonomous agent
to implement a client without reading the server source.

### Embeddable SDK (`remoteshell_client.py`)

For agents, `remoteshell_client.py` is a single-file, dependency-free module
you can drop in and import. It pins the TLS fingerprint (no cert files) and
captures the `X-Exit-Code` trailer, and offers expect/send primitives for
driving interactive (prompting) commands.

```python
from remoteshell_client import RemoteShellClient

rs = RemoteShellClient(
    "https://host:433", password="s3cr3t",
    fingerprint="sha256:fdf7e1aa...",     # printed by the server
)

# one-shot, with exit code
res = rs.run("uname -a")
print(res.output.decode(), res.exit_code)

# interactive command that prompts the user
with rs.open_session(command='python3 -c \'n=input("Name? "); print("Hi", n)\'') as sh:
    sh.read_until("Name?", timeout=8)     # wait for the prompt
    sh.send("Ada\n")                      # answer it
    print(sh.read_until("Hi", timeout=8).decode())
```

## Security notes

This tool runs arbitrary commands with the privileges of the user that
launched it — only run it on hosts and networks you control, for legitimate
remote administration. Always use `--tls` (or a TLS-terminating reverse
proxy) when the server is reachable beyond localhost: without it the
password and all traffic travel in clear text.
