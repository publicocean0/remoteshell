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

## Protocol

- `POST /exec`
  - Header `X-Auth-Token`: the password (compared in constant time).
  - Header `X-Command`: the shell command line to execute.
  - Body (optional): streamed to the command's standard input.
  - Response: chunked stream of the command's stdout+stderr, with the exit
    code in the `X-Exit-Code` trailer.
- `GET /` returns a short status/usage message.

## Security notes

This tool runs arbitrary commands with the privileges of the user that
launched it — only run it on hosts and networks you control, for legitimate
remote administration. The password is sent in clear text over HTTP; put it
behind TLS (e.g. a reverse proxy) or a trusted network if exposed.
