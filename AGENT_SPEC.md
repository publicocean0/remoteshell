# remoteshell — Agent Connection Specification

This document specifies the wire protocol of the `remoteshell` server so that
an autonomous agent (or any programmatic client) can connect and operate it
without reading the server source. It is precise and self-contained.

Protocol version: `remoteshell/1.0`.

---

## 1. Transport

- The server speaks **HTTP/1.1**. It listens on a single host:port (default
  port `433`).
- It may run in plain `http://` or, when started with `--tls`, in `https://`.
- Persistent connections (keep-alive) are supported and SHOULD be reused for
  the many small requests of an interactive session.
- Responses that carry command/terminal output use **chunked transfer
  encoding** and an HTTP **trailer** `X-Exit-Code`.

### 1.1 TLS handshake (certificate pinning / TOFU)

The TLS certificate is **self-signed**; there is no CA chain to validate. The
agent MUST authenticate the server by pinning the certificate's SHA-256
fingerprint:

1. Obtain the expected fingerprint out-of-band. The server prints it once at
   startup as `sha256:<64 hex chars>`.
2. Connect with certificate verification disabled (no hostname check, no CA
   check).
3. Read the server's leaf certificate in DER form and compute
   `sha256(DER)` as lowercase hex.
4. Compare it (constant-time) against the expected fingerprint with `:` and
   the `sha256:` prefix stripped. If it differs, **abort** the connection.

If no expected fingerprint is available, the agent MAY connect once to read
and record the presented fingerprint (TOFU), then require it on every
subsequent connection. It MUST NOT silently accept changing fingerprints.

---

## 2. Authentication

Every endpoint except `GET /` requires the header:

```
X-Auth-Token: <password>
```

The value is the server's launch password. On mismatch the server responds
`401` with a `text/plain` body. The comparison is constant-time server-side;
the token is otherwise opaque.

---

## 3. Endpoints

| Method   | Path                       | Purpose                              |
|----------|----------------------------|--------------------------------------|
| `GET`    | `/`                        | Liveness/usage banner (no auth).     |
| `POST`   | `/exec`                    | Run one command (non-interactive).   |
| `POST`   | `/session`                 | Create an interactive PTY session.   |
| `GET`    | `/session/<id>/output`     | Stream the session's terminal output.|
| `POST`   | `/session/<id>/input`      | Send bytes to the session's terminal.|
| `POST`   | `/session/<id>/resize`     | Change the session's terminal size.  |
| `DELETE` | `/session/<id>`            | Terminate the session.               |

Unknown paths return `404`. Missing/invalid required headers return `400`.

---

## 4. One-shot commands — `POST /exec`

Request:

- Header `X-Auth-Token` (required).
- Header `X-Command` (required): the command line, executed via the server's
  shell (`sh -c <command>` semantics; pipelines, redirection, `&&`, etc. are
  allowed).
- Body (optional): streamed verbatim to the command's **stdin**. Send a
  `Content-Length`; the server reads exactly that many bytes. (The server
  does not decode a chunked request body, so set `Content-Length`.)

Response:

- `200`, `Content-Type: application/octet-stream`,
  `Transfer-Encoding: chunked`, `Trailer: X-Exit-Code`.
- The body is the merged **stdout + stderr** of the command, streamed as it is
  produced (no buffering of the whole output).
- After the final chunk, the trailer `X-Exit-Code: <int>` gives the command's
  exit status. Note: many HTTP libraries silently discard trailers — an agent
  that needs the exit code must read the raw chunked stream itself.

Errors: `400` (missing `X-Command`), `401` (bad token), `500` (spawn failed).

---

## 5. Interactive sessions

Use sessions when the command needs a TTY or live interaction (shell prompts,
`vi`, `top`, `sudo`, REPLs). The server allocates a real pseudo-terminal per
session. The session is driven full-duplex over **separate** connections: one
long-lived `GET …/output` for reading, and short `POST …/input` requests for
writing.

### 5.1 Create — `POST /session`

Request headers:

- `X-Auth-Token` (required).
- `X-Command` (optional): command to run under the PTY. If omitted, an
  interactive shell is launched.
- `X-Rows`, `X-Cols` (optional): initial terminal size (integers).

Response: `201`, `Content-Type: application/json`, body:

```json
{
  "id": "<hex session id>",
  "output": "/session/<id>/output",
  "input": "/session/<id>/input"
}
```

### 5.2 Read output — `GET /session/<id>/output`

- Header `X-Auth-Token` (required).
- Response: `200`, `application/octet-stream`, `Transfer-Encoding: chunked`,
  `Trailer: X-Exit-Code`.
- Streams raw terminal output (includes the PTY's echo of typed input and any
  ANSI/VT escape sequences) until the program exits, at which point the stream
  ends and the `X-Exit-Code` trailer is sent.
- This connection is long-lived; the agent MUST disable any read timeout while
  consuming it. Open it **once** per session (a single reader).

### 5.3 Send input — `POST /session/<id>/input`

- Headers `X-Auth-Token` (required) and `Content-Length`.
- Body: raw bytes written verbatim to the terminal. Include a trailing `\n`
  to represent Enter. Control characters work because the PTY is in cooked
  mode, e.g. `\x03` = Ctrl-C (SIGINT), `\x04` = Ctrl-D (EOF), `\x1a` = Ctrl-Z.
- Response: `200` `text/plain` (`ok`). Read the full response before issuing
  the next request on a reused connection.
- `404` if the session does not exist (e.g. it already exited).

### 5.4 Resize — `POST /session/<id>/resize`

- Headers `X-Auth-Token`, `X-Rows`, `X-Cols` (integers).
- Response: `200`. Use after the agent's notion of terminal size changes.

### 5.5 Terminate — `DELETE /session/<id>`

- Header `X-Auth-Token`.
- Kills the process and frees the PTY. Response `200`, or `404` if unknown.
- A session also ends on its own when its program exits; the `output` stream
  closing is the authoritative end-of-session signal.

---

## 6. Status codes

| Code  | Meaning                                                      |
|-------|--------------------------------------------------------------|
| `200` | OK (banner, input accepted, resized, terminated, exec/output stream). |
| `201` | Session created.                                             |
| `400` | Missing/invalid required header.                             |
| `401` | Missing or wrong `X-Auth-Token`.                             |
| `404` | Unknown path or unknown session id.                          |
| `500` | Server-side failure starting the command/session.           |

---

## 7. Recommended agent algorithm

**One-shot:**

```
conn = connect(url, pinned_fingerprint)        # verify fingerprint on TLS
POST /exec
    headers: X-Auth-Token, X-Command, Content-Length=len(stdin)
    body:    stdin bytes (optional)
read chunked body -> command output
read trailer X-Exit-Code -> exit status
```

**Interactive:**

```
POST /session  (X-Auth-Token [, X-Command] [, X-Rows/X-Cols]) -> {id}

# reader connection (no read timeout):
GET /session/{id}/output (X-Auth-Token)
  loop: read decoded chunk -> append to transcript / parse
  on stream end: session finished (read X-Exit-Code trailer if needed)

# writer connection (reused, keep-alive):
to act: POST /session/{id}/input  body=<bytes incl. '\n'>; read 'ok'

# when done early:
DELETE /session/{id}
```

Agent guidance for interactive use:

- Drive the terminal by writing input and observing the streamed output;
  treat the output as a possibly-VT100 stream (strip/interpret escapes as
  needed). Wait for a recognizable prompt or expected substring before
  sending the next input rather than fixed sleeps.
- Send one logical action per `input` POST, each ending with `\n`.
- To cancel a running foreground program send `\x03`; to end stdin send
  `\x04`; to leave a shell send `exit\n`.

---

## 8. Minimal examples (curl)

```sh
TOK='X-Auth-Token: s3cr3t'

# one-shot
curl -sS --cacert /dev/null -k https://HOST:433/exec -H "$TOK" -H 'X-Command: uname -a'

# session
ID=$(curl -sk -X POST https://HOST:433/session -H "$TOK" \
     | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -sk -N https://HOST:433/session/$ID/output -H "$TOK" &     # reader
printf 'whoami\n' | curl -sk -X POST https://HOST:433/session/$ID/input -H "$TOK" --data-binary @-
printf 'exit\n'   | curl -sk -X POST https://HOST:433/session/$ID/input -H "$TOK" --data-binary @-
```

> `-k` disables curl's CA check; for real pinning compute and compare the
> certificate fingerprint as described in §1.1 (see `rsh-client.py` for a
> reference implementation).
