# slk serve

`slk serve` is a fork-only subcommand. It runs a small HTTP API on your own
machine so that [Workcenter](https://workcenter.quick.shopify.io) can use your
signed-in Slack session from your browser. It works like `opencode serve`:
the browser calls `127.0.0.1` with a password that only you have, and the
Slack credentials (the xoxc token and the `d` cookie) never leave the process.

This page covers v0 part 1 (Workcenter card WC-2): auth, health and
workspaces. The full contract and threat model come with WC-1.

## Run it

```sh
slk --add-workspace                     # once: reads the Slack desktop app
slk serve --port 4097 --cors https://workcenter.quick.shopify.io
```

```
slk serve dev listening on http://127.0.0.1:4097
  allowed origin: https://workcenter.quick.shopify.io
  username:       slk
  password:       3q2-7xLk…
  (a new password every time slk serve starts; set SLK_SERVER_PASSWORD to keep one)
```

| Flag / env | Default | Meaning |
|---|---|---|
| `--port` | `4097` | Port on `127.0.0.1`. The server never binds any other address. |
| `--cors` | none | The one browser origin allowed to call the server. A request with any other `Origin` header (including `null`) is refused with 403. Without `--cors`, every browser request is refused and only non-browser clients like `curl` work. |
| `SLK_SERVER_PASSWORD` | random | Use this password instead of a fresh random one. It must be at least 16 characters, and the banner doesn't print it. |

## Security

Any web page you visit can send requests to `localhost`, and this server can
post to Slack as you. So every request has to pass all of these checks, in
this order, before it reaches an endpoint:

1. **Host** must be `127.0.0.1:<port>` or `localhost:<port>`. Anything else
   gets a 403. This blocks DNS rebinding.
2. **Origin**, if present, must equal `--cors` exactly, or the request gets a
   403. A CORS preflight (`OPTIONS`) from the allowed origin gets a 204 with no
   auth needed, and includes `Access-Control-Allow-Private-Network: true` for
   Chrome's Private Network Access check.
3. **HTTP basic auth** with user `slk` and the password, compared in constant
   time. Anything else gets a 401.

The password is printed once, in the startup banner. After that, every log
line passes through a redactor that removes the password, every token and
cookie the process has loaded, and anything shaped like a Slack token
(`xox?-…`). Request logs record the method, path, status and duration only,
never headers or query strings.

## Endpoints

Every response is JSON. Errors look like
`{"error": {"code": "unauthorized", "message": "…"}}`.

### `GET /v0/health`

```json
{
  "ok": true,
  "server": {"version": "dev", "startedAt": "…", "uptimeSeconds": 12,
             "listen": "127.0.0.1:4097", "corsOrigin": "https://workcenter.quick.shopify.io"},
  "auth": {"state": "ok", "source": "desktop", "lastRefreshAt": "…", "lastRefreshReason": "startup"},
  "workspaces": [{"id": "E017D49VC3F", "name": "Shopify", "state": "connected",
                  "userId": "W018WBRF44R", "lastCheckedAt": "…"}]
}
```

- `ok` is true when auth is `ok` and at least one workspace is connected.
- `auth.state` is one of `starting`, `ok`, `refreshing`, `expired` or `error`.
- `auth.source` is `desktop` when the last refresh read the live Slack desktop
  session, or `cached` when it fell back to the tokens saved by
  `--add-workspace`.
- `workspaces[].state` is one of `connecting`, `connected`, `auth_expired` or
  `error`. The `error` field holds a short, redacted reason.

### `GET /v0/workspaces`

Lists the workspaces that are connected right now. The `id` values are the
team IDs that later endpoints are keyed on (the same IDs as
`slk --list-workspaces`).

```json
{"workspaces": [{"id": "E017D49VC3F", "name": "Shopify", "domain": "shopify.enterprise", "userId": "W018WBRF44R"}]}
```

### `POST /v0/auth/refresh`

Re-reads the live Slack desktop session, then reconnects. Returns the same
body as `/v0/health`. A refresh that finished less than 10 seconds ago is
reused instead of running again.

## Sessions and expiry

xoxc tokens expire, and the Slack desktop app holds the current session. The
server re-reads the desktop app's cookie and tokens (and saves them to the
token store, as the TUI does at launch) in these cases:

- at startup;
- when a periodic `auth.test` (every 5 minutes) is rejected with
  `invalid_auth`, `not_authed`, `token_revoked`, `token_expired` or
  `account_inactive`;
- while any workspace is down, with backoff from 1 to 10 minutes;
- on `POST /v0/auth/refresh`.

So if Slack signs you out, signing back in to the desktop app is enough.
`slk serve` picks the new session up without a restart.

## Code layout

- `cmd/slk/serve.go` holds the `serve` case: flags, the banner, tokens,
  desktop-session refresh and connection state. It lives in `cmd/slk` to reuse
  the workspace config store, the token remint and, later, the user resolver
  and history helpers.
- `internal/server` holds HTTP only: the bind, the guards, CORS, JSON and
  redaction. It never sees a credential. Slack access goes through its
  `Backend` interface.

Upstream files touched: only `cmd/slk/main.go`, to add the `serve` case and a
help line, so the fork rebases cleanly.
