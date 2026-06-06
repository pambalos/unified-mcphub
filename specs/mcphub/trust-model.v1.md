# Two-hop trust model — OpenClaw → hub → upstream (UAI-112)

Status: **doc** · Target milestone: M0.8 · Relates to: UAI-108 (connection), UAI-109/107 (approvals)

When OpenClaw drives a tool call through the hub to a third-party server, the
request crosses **two distinct trust boundaries with two distinct auth models**.
Keeping them separate is what lets upstream credentials stay fully dynamic while
no static secret ever lands in OpenClaw config.

```
OpenClaw ──(local hop)──▶ unified-hub ──(upstream hop)──▶ third-party MCP server
          unix-socket /                 OAuth 2.0
          per-caller bearer             (Auth Code + PKCE, refresh rotation)
```

## Hop 1 — OpenClaw → hub (local, same-host)

- **Transport:** unix socket (primary, `0600`) or TCP loopback. OpenClaw's MCP
  client is HTTP-only, so the installed connection uses the hub's TCP
  `streamable-http` endpoint (see UAI-108 / `installers/openclaw.py`).
- **Auth:** a per-caller **bearer token** minted for the `openclaw` caller
  (`tokens.py`, `TokenStore.mint`) + an `X-Caller-Id: openclaw` header. The token
  is a local, same-host credential; it identifies *who* is calling for authz and
  audit (`caller_token_id`).
- **Why not OAuth here:** both ends are processes you own on one box. OAuth's
  value — delegated, refreshable, revocable *third-party* access — does not apply
  to a same-host trust boundary; an OAuth server there is ceremony for marginal
  gain. (See the DESIGN trust-boundary note.) mTLS is the optional hardening if
  this hop is ever exposed over TCP off-box.
- **What does NOT live in OpenClaw:** no upstream API keys, no upstream OAuth
  tokens. OpenClaw holds only its single local bearer to the hub.

## Hop 2 — hub → upstream (third-party)

- **Auth:** the hub is an OAuth **client** — Authorization Code + PKCE, dynamic
  client registration via `.well-known/oauth-authorization-server`, and
  **refresh-token rotation** (`oauth.py:OAuthFlow.refresh`, persisted through the
  secrets store / OS keyring). This is the hop where OAuth earns its keep:
  third-party tokens expire and must rotate.
- **Where tokens live:** refresh tokens persist **only** in the hub's secrets
  store (OS keyring), never in OpenClaw state or config. Access tokens are
  injected by the hub as the upstream auth header.
- **When refresh happens (current wiring):** auth is resolved **per (re)connect**
  to the upstream (`supervisor.py`). If the server has an `oauth:` block and a
  refresh token exists (i.e. `auth login` was run), the hub calls `flow.refresh()`
  to mint a fresh access token and rotates the refresh token if the provider
  returns a new one. Any failure degrades to no-auth and the upstream is marked
  unhealthy — it never silently runs unauthenticated.

## What's proven vs. open

- **Proven (unit-tested):** PKCE challenge, state validation, code exchange
  persists the refresh token, and **refresh rotates** the stored token
  (`tests/unit/test_oauth.py::test_refresh_rotates_token`,
  `test_exchange_persists_refresh_token`). No static secret is required at call
  time once `auth login` has run.
- **Open (the e2e half of UAI-112):** an end-to-end proof that an
  OpenClaw-driven call survives access-token expiry transparently. Today refresh
  is **connect-time**, so a mid-session expiry refreshes on the next reconnect,
  not mid-call. Fully satisfying the "force-expire mid-session → silent refresh,
  no operator action" acceptance needs either (a) a per-call **refresh-on-401**
  retry in the forward path, or (b) proactive refresh-before-expiry. Tracked as
  the remaining UAI-112 work; this doc is the documented half.

## Net property

Everything dynamic and auto-refreshed lives where it matters (hub → upstream),
and the local hop stays a simple, auditable same-host bearer. No upstream secret
is ever present in OpenClaw config or state.
