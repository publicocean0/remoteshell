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

## Security notes

This tool runs arbitrary commands with the privileges of the user that
launched it — only run it on hosts and networks you control, for legitimate
remote administration. The password is sent in clear text over HTTP; put it
behind TLS (e.g. a reverse proxy) or a trusted network if exposed.
