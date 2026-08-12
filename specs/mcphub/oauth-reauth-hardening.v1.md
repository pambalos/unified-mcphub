# Plan — OAuth re-auth hardening: secrets single-writer + hub-hosted callback

Status: **proposed** · Target milestone: M0.9 · Owner: Bradley

Goal: eliminate the two sharp edges in the hub's upstream-OAuth lifecycle. **(1)**
Close the one remaining way stored credentials can be silently corrupted — a CLI
credential write racing the running hub's refresh-token rotation. **(2)** Kill the
manual copy-paste (and manual restart) in `auth login` by hosting the OAuth
callback on the port the hub already owns, so re-auth becomes *click-Approve-done*
and the server reconnects itself.

Motivating incident: on 2026-07-06 Linear's stored refresh token expired; the hub
logged `POST /token → 400` then `/mcp → 401`, the `linear` server never connected,
and **zero `mcp__unified-hub__linear__*` tools loaded**. Recovery required
`auth revoke linear` + `auth login linear` (copy-paste the redirect URL) +
`gateway restart`. This plan makes that recovery near-frictionless and rarer.

---

## What already works (do not rebuild)

- **Single-writer across *hub instances* is already enforced.** `AuditLog.start()`
  takes an `fcntl.LOCK_EX | LOCK_NB` exclusive lock on `~/.unified-ai/mcphub/audit/.lock`
  (`audit.py:80-87`), inside `Hub.start()` (`hub.py:153`) **before any OAuth
  refresh**. The path is home-scoped (`audit_dir() = mcphub_home()/audit`, constant
  across workspaces *and* git worktrees — `config.py:54`). A second full hub against
  the same home dies with *"audit log is locked by another hub."* `fcntl` locks
  auto-release on process death, so there is no stale-lock hazard. **We rely on this;
  we do not duplicate it.**
- **Refresh-on-(re)connect** already resolves auth per connection
  (`supervisor.py:57-76`), and **refresh tokens rotate** (`oauth.py:105-107`).
- **DCR registers the loopback redirect** `http://127.0.0.1:7712/oauth/callback`
  (`oauth.py:20` `DEFAULT_REDIRECT_URI`, registered at `oauth.py:141`). Piece 2
  reuses this exact URI — no re-registration.

---

## Locked decisions

1. **Two independently-shippable pieces.** Piece 1 (secrets single-writer) is a
   small root-cause safety fix with no API/config change and ships on its own.
   Piece 2 (hub-hosted callback) is the UX change. Piece 2 depends on Piece 1 only
   in that it should not re-introduce an unlocked write path.
2. **The real gap is CLI-vs-hub, not hub-vs-hub.** The audit lock covers concurrent
   hubs. It does **not** cover the standalone CLI mutations (`auth login`,
   `auth revoke`, `secrets set`), which write `secrets.enc` without any lock while
   the hub may be rotating a refresh token. Piece 1 fixes exactly this.
3. **Lock at the secrets read-modify-write, not around the whole process.** Both the
   hub and every CLI invocation run the same `SecretsStore` code, so a short
   `fcntl` critical section inside `set()`/`remove()` serializes *all* writers with
   no long-held locks.
4. **Host the callback where the port already is.** The registered redirect URI is
   `127.0.0.1:7712/oauth/callback` and the running hub is already bound there. The
   reason `auth login` pastes today is that it runs as a *separate process* that
   cannot bind 7712. Moving the callback into the hub's existing Starlette app
   removes the paste with zero redirect-URI churn.
5. **The consent click is unavoidable.** Authorization Code + PKCE requires a human
   to approve at Linear/Notion. This plan minimizes friction around that click; it
   does not (and cannot) remove it. Fully-silent re-auth is explicitly a non-goal.
6. **Graceful degradation, three tiers.** hub-hosted callback (primary) →
   standalone loopback listener when the hub is down → manual paste as the
   last-resort headless fallback. No path regresses today's capability.

---

## Piece 1 — Secrets single-writer lock

### The race (concrete)

The hub's refresh path writes the store: `flow.refresh()` → `_persist_refresh()` →
`SecretsStore.set(f"{server}-oauth-refresh", …)` (`oauth.py:105-107`,
`secrets.py:103`). A standalone `auth login` writes a *fresh* token via
`exchange_code()` to the same key. Interleaving:

1. `auth login` completes, stores fresh `T_new`.
2. The hub — mid reconnect of that server — refreshes the *old* chain `T_old → T_old2`
   and calls `set(...)`, its `_load()` having happened before step 1's `_save()`.
3. `T_old2` clobbers `T_new`. The just-authorized token is lost; next reconnect
   refreshes a superseded chain → provider 400 → server down again.

Narrow (requires overlap with an active reconnect) but real, and it fails in the
most confusing possible way: *"I just re-authed and it's still broken."*

### Design

Add a blocking exclusive `fcntl` lock around the load→mutate→save sequence in
`SecretsStore`, on a sidecar lock file `secrets.enc.lock` (mode 0600, beside
`secrets.enc`).

- **New:** `SecretsStore._locked_write()` context manager — `os.open` the lock
  file `O_CREAT|O_RDWR`, `fcntl.flock(fd, LOCK_EX)` (blocking — we *want* to wait
  for the other writer), `yield`, then release + close. Mirror the `fcntl` idiom
  already in `audit.py:80`.
- **Wrap** the read-modify-write in `set()` (`secrets.py:103`) and `remove()`
  (`secrets.py:111`) so `_load()` and `_save()` execute inside one held lock.
  Pure reads (`get()`, `list()`) stay lock-free (single atomic `secure_write`
  means a reader sees either the old or new file, never a torn one).
- **Timeout guard:** wrap the blocking `flock` in an `alarm`/`SIGALRM`-based or
  bounded-retry timeout (~5 s) so a writer that dies mid-section can't wedge
  another process. `fcntl` already releases on death; this only covers a pathological
  hang.

### Touch points
- `secrets.py`: `_locked_write()` (+ lock-path helper), wrap `set()`/`remove()`.
  ~12–15 lines. No changes to `config.py`, no new config keys, no API change.

### Edge cases
- **`env`/`file` key backends:** unchanged — the lock guards the encrypted blob
  write, independent of where the master key lives.
- **First-ever write (no `secrets.enc` yet):** `_locked_write()` still creates the
  lock file; `_save()` creates the store. Fine.
- **Windows:** `fcntl` is POSIX-only (already true of `audit.py`, so the hub is
  effectively POSIX today). Guard the import and no-op the lock on non-POSIX with a
  logged warning, matching the existing platform posture.

### Tests
- Concurrency test: two threads/processes call `set()` on the same store with
  distinct keys; assert both survive (no lost update). Repeat with the *same* key
  to assert last-writer-wins is clean (no torn/corrupt decrypt).
- Regression: existing secrets unit tests pass unchanged.

---

## Piece 2 — Hub-hosted OAuth callback (Tier 3)

### Primary path — hub is running

1. **New hub routes** in `transports.py build_app()` (same Starlette app already
   serving `/mcp`, `/status`, `/approvals/*` on TCP 7712 + UDS):
   - `POST /oauth/login/start` — authed via existing `_authenticate()`
     (`transports.py:46`). Body `{server}`. Hub builds the flow with
     `oauth.build_flow(server, self.secrets, …)` (same args as `cli.py:203-212`),
     stashes it keyed by `state` (`hub._oauth_pending[state] = flow`), returns
     `{authorize_url, state}`.
   - `GET /oauth/callback?code=&state=` — **unauthenticated by design**: the browser
     hits it directly and security is the `state` + PKCE verifier (identical to any
     OAuth client). Hub looks up the pending flow by `state`, calls
     `flow.exchange_code(code, state)` (persists the refresh token via
     `self.secrets`, now under Piece 1's lock), then **reconnects that one server**.
     Returns a real HTML page: *"✓ Authorized {server} — you can close this tab"*
     (fixes today's "page won't load" wart). Unknown/expired `state` → 400 HTML.
   - `GET /oauth/login/status?state=` — CLI polls this to completion
     (`pending | authorized | error`).
2. **CLI** (`cmd_auth`, `cli.py:189`): `auth login <server>` becomes a thin client —
   detect a reachable hub (UDS preferred, TCP fallback; reuse the client transport),
   `POST /oauth/login/start`, `webbrowser.open(authorize_url)`, poll
   `/oauth/login/status` until terminal, print result. **No paste, no restart.**
3. **Auto-reconnect:** add `Hub.reconnect_server(name)` (stop-one + start-one; the
   supervisor already re-resolves auth per connect, `supervisor.py:57-76`). This is
   the "no manual restart" win, and it makes the **hub the sole token writer on the
   common path** — folding Piece 1's guarantee in for free here.

### Fallback paths (no regression)
- **Hub down:** the CLI binds `127.0.0.1:7712` itself (free when the hub is down),
  runs a one-shot stdlib `http.server` handler for `/oauth/callback`, opens the
  browser, captures the redirect automatically, exchanges, stores (under Piece 1's
  lock). Still no paste.
- **Headless / no browser (SSH):** keep today's manual-paste flow (`cli.py:213-230`)
  as the last resort, selected by a `--manual` flag or auto-detected on
  `webbrowser.open` failure.

### Constraints (call out in help text)
- The browser can only reach the **TCP** listener (`127.0.0.1:7712`), never the UDS.
  So the hub-hosted path needs TCP enabled; `--no-tcp` deployments use the
  standalone-listener fallback.
- Redirect-URI matching is free: `7712/oauth/callback` is exactly what DCR
  registered (`oauth.py:141`), so no re-registration, no port juggling on the
  primary path.

### Touch points
- `transports.py`: three routes + a small HTML helper. Thread `hub._oauth_pending`.
- `hub.py`: `_oauth_pending` dict; `reconnect_server(name)`.
- `cli.py`: rewrite `cmd_auth` login branch (client + poll + browser); `--manual`
  flag; keep `revoke` as-is (now lock-guarded via Piece 1).
- `oauth.py`: no change to the flow; possibly expose a helper so the hub and the
  standalone fallback share one code path.

### Edge cases
- **`state` reuse / stale pending:** expire `_oauth_pending` entries after a few
  minutes; unknown state → 400.
- **Two logins in flight:** keyed by `state`, so concurrent logins for different
  servers are fine.
- **Callback arrives after hub restart:** pending state is in-memory; a restart
  invalidates it → clean 400 + "start over." Acceptable.
- **Reconnect fails post-exchange** (token good but server flaky): report authorized
  + a reconnect warning; the token is saved, so a later reconnect/restart succeeds.

### Tests
- Unit: `/oauth/callback` route with a mocked `exchange_code` → asserts token
  persisted + `reconnect_server` called + success HTML.
- e2e: fake OAuth authorization server (reuse `tests/e2e` + `tests/fixtures`) drives
  start → browser-sim GET callback → status=authorized → tools reappear.
- Manual: live Linear + Notion re-auth dry run end-to-end.

---

## Sequencing & effort

| Order | Piece | Effort | Ships alone? |
|------|-------|--------|--------------|
| 1 | Secrets single-writer lock | ~0.5 day incl. tests | Yes |
| 2 | Hub-hosted callback + CLI + reconnect | ~1.5–2 days | Yes (after 1) |

Recommendation: land Piece 1 first as its own PR (clean, independently valuable
safety fix), then Piece 2.

---

## Planned Linear tickets

Team: **Unified-AI** (`d9b4115e-…`). Parent/epic optional; the two work items are
independent PRs. Proposed as a small epic + 4 issues.

- **[Epic] OAuth re-auth hardening (secrets single-writer + hub-hosted callback)**
  Umbrella; links this spec. Acceptance: both PRs merged, Linear/Notion re-auth
  verified with no paste and no manual restart, secrets concurrency test green.

- **UAI-### · Secrets single-writer lock** (Piece 1)
  `fcntl` lock around `SecretsStore.set/remove`; timeout guard; POSIX-guard for
  Windows. *AC:* concurrent-writer test proves no lost update; no config/API change;
  existing secrets tests pass. *Est: S.*

- **UAI-### · Hub-hosted OAuth callback routes + auto-reconnect** (Piece 2a)
  `/oauth/login/start`, `/oauth/callback`, `/oauth/login/status` in `transports.py`;
  `Hub._oauth_pending` + `Hub.reconnect_server`. *AC:* callback exchanges + persists
  + reconnects one server without a full restart; success/erroring HTML; stale-state
  → 400. *Est: M.* *Depends on Piece 1.*

- **UAI-### · `auth login` no-paste CLI (browser + poll + fallbacks)** (Piece 2b)
  Rewrite `cmd_auth` login branch to drive the hub path; standalone-listener
  fallback when the hub is down; `--manual` last-resort. *AC:* re-auth completes with
  only an in-browser Approve click on the primary path; `--manual` preserves today's
  behavior; `--no-tcp` documented to use the fallback. *Est: M.* *Depends on 2a.*

- **UAI-### · Re-auth UX docs + health-probe note**
  README "Re-authenticating an OAuth server" section (the three tiers); cross-link
  from the OAuth-failure log signature (`400 /token → 401 /mcp`). Optional: note the
  external cron health-probe (the separate "Tier 1" monitor) as the proactive
  companion. *Est: S.*

Open questions to resolve before ticket creation:
1. Completion signalling — CLI **polling** (least code, recommended) vs. reuse the
   existing **SSE** broadcaster (`transports.py:86`)?
2. Success page — auto-close vs. static confirmation text?
3. Create the epic as a Linear **Project** or a parent **Issue** with sub-issues?
