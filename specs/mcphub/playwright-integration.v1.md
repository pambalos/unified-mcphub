# Plan — playwright integration: an optional full-browser MCP server

Status: **proposed** (upstream recon 2026-06-02 — see Verified facts) · Target
milestone: M0.75+ (after `add-server`) · Owner: TBD

Goal: give an agent the ability to **navigate and browse the live internet through
a real browser** (Chromium/Firefox/WebKit) over MCP — as an **optional, opt-in
install**, never part of the default tiny tier — integrated behind the hub's
default-deny authz, approval, and audit just like every other upstream.

The headline decision (below): **do not write or re-implement a browser server.**
Integrate Microsoft's official **`@playwright/mcp`** (npm) the same way `add-server`
already wires the `server-memory` npx worked example — pinned, hardened launch
flags, and a curated default-deny rule set. The "optional install" is the
**provisioning** of Node + the pinned package + the heavy **browser binaries**
(the heaviness analog to graphify's tree-sitter grammars), plus a documented
hardened launch profile. This mirrors the `unified-mcp-graphify` *posture*
(optional / heavy / out-of-workspace) without copying its *mechanism* (a Python
wrapper), because the upstream here is Node and is best consumed as-is.

---

## Verified facts (upstream review — 2026-06-02)

From [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)
`main` README + `package.json`. Re-confirm the version-pinned details in Phase 0
(the package ships frequently).

- **Package = `@playwright/mcp`** (npm, scoped). Run via
  `npx @playwright/mcp@<ver>`. **Node `>=18`** required. Current published
  version observed: **`0.0.75`** (pin this, do not use `@latest` — see
  Supply-chain posture). License: Apache-2.0 (Microsoft) — redistribution/wrapping
  permitted; **confirm in Phase 0** before any vendoring.
- **Global bin name** (for the rung-4 pre-install path) reads as **`playwright-mcp`**
  in `package.json` `bin`. ⚠️ Some older releases used `mcp-server-playwright`.
  **Verify by running `npm i -g @playwright/mcp@<ver> && which playwright-mcp`** in
  Phase 0 before writing it into a `--command` entry.
- **Two transports.** Default is **stdio** (what the hub drives). `--port` switches
  it to streamable-HTTP. Use **stdio** — no listening port, no extra surface.
- **Browser binaries are a separate, heavy download.** The npm package is small;
  the actual browsers come from `npx playwright install <browser>` (Chromium alone
  is hundreds of MB). This is the real "heaviness" and the reason this is an
  **opt-in install**, not bundled. Without the install step the server starts but
  every `browser_navigate` fails with "browser not installed."
- **Default profile is PERSISTENT and headed.** By default it keeps a persistent
  profile (cookies/logins survive restarts) at an OS cache dir, and runs **headed**.
  Two flags change this for agent use: **`--isolated`** (ephemeral profile, storage
  lost on close) and **`--headless`**. A persistent profile **cannot run
  concurrently from the same workspace** — relevant if two harnesses both point at
  the hub's one Playwright upstream.
- **Network/origin controls exist at the server (these are the only per-URL
  controls — the hub gates *tools*, not *URLs*). Semantics verified locally
  2026-06-02 against `0.0.75`:**
  - `--allowed-origins <origins>` — semicolon-separated **allowlist**; only listed
    origins reachable, everything else (other sites *and* all loopback ports)
    blocked. Robust SSRF containment; the high-security option. ✅ tested.
  - `--blocked-origins <origins>` — semicolon-separated **denylist**. ⚠️ Origins
    are matched **scheme + host + port**, so a bare `http://127.0.0.1` does **not**
    block `:7712` — you must use a **port glob** `http://127.0.0.1:*`. Host globs
    also work (`http://10.*:*`). Public internet stays reachable. ✅ tested:
    blocked `example.com`/loopback exactly, port+host wildcards block as expected.
  - `--allowed-hosts <hosts...>` — comma-separated host allowlist.
  - `--allow-unrestricted-file-access` — (off by default) lets the browser read
    files beyond workspace roots. **Leave OFF.**
- **Sandbox + isolation flags:** `--sandbox` / `--no-sandbox`,
  `--isolated`, `--user-data-dir <path>`, `--storage-state <path>`,
  `--shared-browser-context`, `--browser chromium|firefox|webkit|msedge`,
  `--executable-path`, `--extension` (attach to a running Chrome/Edge — **do not
  use**, breaks isolation).
- **Capabilities are opt-in via `--caps`.** Core automation tools are always on;
  extra families load only when named: `vision`, `pdf`, `devtools`, `storage`,
  `network`, `testing`, `config`. **Default to NO extra caps for v1.**
- **Tool surface** (core, always on, ~22 tools): `browser_navigate`,
  `browser_navigate_back`, `browser_click`, `browser_type`, `browser_fill_form`,
  `browser_select_option`, `browser_hover`, `browser_drag`, `browser_drop`,
  `browser_press_key`, `browser_file_upload`, `browser_handle_dialog`,
  `browser_resize`, `browser_wait_for`, `browser_snapshot` (accessibility-tree
  snapshot — the primary "what's on the page" read), `browser_take_screenshot`,
  `browser_console_messages`, `browser_network_requests`, `browser_network_request`,
  `browser_tabs`, `browser_close`, **`browser_evaluate`** (runs arbitrary JS in the
  page), **`browser_run_code_unsafe`** (runs arbitrary Playwright code — the name
  is a warning). Cap-gated families add `browser_pdf_save` (pdf), the
  `browser_mouse_*_xy` set (vision), `browser_cookie_*` / `browser_localstorage_*`
  / `browser_storage_state` (storage), `browser_route*` (network), etc.
- **Hub plumbing already supports this.** `add-server`'s `--npx PKG` shorthand
  emits `command: npx, args: ["-y", PKG, …]`; its `preflight()` hard-errors if
  `npx` isn't on PATH; its probe warms the npx cache before `list_tools` so the
  first-fetch latency doesn't race the supervisor's 30s `wait_ready`. The
  supervisor only rewrites bare `python` to the hub venv (`supervisor.py:62`), so
  `npx`/`node` must be on PATH — exactly the `server-memory` situation already
  documented.

---

## Core decision — integrate the official server; do NOT re-implement

| Option | Verdict |
|---|---|
| **A. Config-only integration of `@playwright/mcp`** (pinned npx or pre-installed bin, hardened flags, curated authz) | **CHOSEN for v1.** Official, maintained, complete tool surface, native origin/sandbox controls. Zero tool-surface code to write or re-sync. |
| **B. Python re-implementation** via the `playwright` pip package (write all ~22 `browser_*` tools as a `unified-mcp-*` server) | **Rejected.** Re-implements a fast-moving official server — the exact re-sync churn the graphify spec rejected ("144 releases"). No upside: we'd reproduce Microsoft's tools worse. |
| **C. Thin Python *launcher* wrapper** (no tools; just `os.execvp`s `npx @playwright/mcp@<pin>` with hardened flags baked in, + a `playwright install` bootstrap subcommand) | **Deferred to v1.5.** Genuine value — owns the pin, guarantees the hardened flags can't be forgotten, gives a stable rung-4 `--command`. But it adds a Node-dep'd Python package; only worth it if "forgotten flags" / pin-drift bite in practice. |
| **D. Egress-gating proxy wrapper** (interpose per-URL allow/deny + audit between the agent and the browser) | **Deferred to v2.** The only way to get *hub-level, audited, per-URL* gating instead of relying on the server's `--allowed-origins`. Real but not needed for the target use case. |

**Why this differs from graphify.** graphify is a Python engine whose wrapper added
real capability (`build_graph` over MCP, per-call `path`). `@playwright/mcp` is a
complete Node server that needs no capability added — only **provisioning,
hardening, and gating**, all of which are config + docs. So v1 ships **no new
package**; the deliverable is an *integration* (an "Optional servers" README row, a
provisioning recipe, a hardened launch profile, and a curated rule set), parallel
in spirit to the graphify row but lighter in mechanism.

> If the team prefers strict symmetry with graphify (every optional server is a
> `packages/unified-mcp-*` dir), promote Option C to v1 — the package would be
> tiny (a launcher + an install subcommand, no tools) and still excluded from the
> uv workspace. Flagged as an open point below.

---

## The optional install (provisioning — the heavy, opt-in step)

Three things must be present; none ship by default:

1. **Node `>=18`** on PATH (provides `npx`). Prereq, not installed by us; the
   `add-server` `preflight()` already hard-errors with a hint if `npx` is missing.
2. **The pinned MCP package.** Either fetched-at-spawn via pinned npx (rung 2) or
   pre-installed (rung 4 — recommended): `npm i -g @playwright/mcp@<ver>`.
3. **The browser binaries** (the heavy part): `npx playwright install chromium`
   (add `--with-deps` on Linux/CI for the system libs). Chromium-only keeps the
   download to one browser; add `firefox`/`webkit` only if needed.

Document this as a copy-paste block in the README (see Docs below). The
security-conscious / gold path is rung 4 + Chromium-only:

```sh
# one-time provisioning (opt-in, heavy: pulls a full browser)
npm i -g @playwright/mcp@0.0.75          # pin — never @latest
npx playwright install chromium          # the browser binaries (hundreds of MB)
# register the pre-installed bin with the hub (no fetch-at-spawn)
uv run unified-mcphub add-server playwright \
  --command playwright-mcp \
  --arg --headless --arg --isolated \
  --arg --blocked-origins --arg '<see hardened profile below>'
```

(`playwright-mcp` = the global bin — **confirm the exact name in Phase 0**.)

---

## Heaviness / isolation

Consistent with graphify's isolation rule: **never a dependency of the hub core or
the `unified-mcp-servers` tiny tier, and never in the default workspace.** Here the
weight is the **browser binaries + Node toolchain**, which live entirely outside
this Python repo — so there is *nothing to exclude from the uv workspace* (unlike
graphify) unless Option C adds a launcher package, which would carry
`[tool.uv.workspace] exclude` for the same reason.

---

## Hardened launch profile (the security-relevant flags)

Browsing the live internet is a large attack surface. Bake these into the upstream
`args` (or the launcher in Option C). Rationale per flag:

- **`--headless`** — no visible window; correct for an agent. (Headed only for
  human debugging.)
- **`--isolated`** — ephemeral profile; no persisted cookies/logins/credentials
  that a later session (or a prompt-injected page) could exfiltrate. Drop this only
  with a deliberate `--storage-state`/`--user-data-dir` for an authenticated
  workflow, and treat that profile as a secret.
- **`--blocked-origins`** — **seed it with the cloud-metadata + loopback ranges
  using PORT GLOBS** (`http://127.0.0.1:*;http://localhost:*;http://[::1]:*;http://169.254.169.254:*`),
  mirroring the `fetch` server's opt-in SSRF blocklist (`fetch.py:40`). ⚠️ Verified:
  a bare host without `:*` only blocks port 80 — use the glob. A browser that can
  reach `http://169.254.169.254/` or `http://localhost:<hub>` is an SSRF pivot.
  This is the **only** per-URL control available (the hub gates tools, not URLs).
- **`--allowed-origins`** — for a locked-down deployment, flip to an *allowlist*
  (the browser may reach only named origins). Strongest containment; document as
  the high-security option.
- **Leave OFF:** `--allow-unrestricted-file-access` (keeps the browser out of the
  FS beyond workspace roots), `--extension` (would attach to the operator's real
  browser, defeating isolation), `--port` (no HTTP transport — stdio only).
- **`--caps`:** none for v1. Each cap (`vision`/`pdf`/`devtools`/`storage`/
  `network`) widens the surface; add only on demonstrated need.
- **Concurrency note:** one hub → one Playwright upstream → one browser context. A
  persistent (`--user-data-dir`) profile **can't run concurrently from the same
  workspace**; `--isolated` (the default here) sidesteps it. If multiple harnesses
  drive the hub at once, document that browser tool calls serialize.

---

## Authz / config sketch (added via `add-server`)

```yaml
servers:
  playwright:
    enabled: true
    upstream:
      command: npx                       # or: command: playwright-mcp  (rung-4 bin)
      # PIN the version — require_pinned_versions (default on) refuses an unpinned
      # fetch-and-run upstream at load.
      args: ["-y", "@playwright/mcp@0.0.75",
             "--headless", "--isolated",
             # port globs (:*) required — bare host only blocks port 80 (verified)
             "--blocked-origins", "http://localhost:*;http://127.0.0.1:*;http://[::1]:*;http://169.254.169.254:*"]
# authz (probe proposes; OPERATOR MUST CURATE — see note):
#   reads        → allow:  browser_snapshot, browser_take_screenshot,
#                          browser_console_messages, browser_network_requests,
#                          browser_network_request, browser_tabs, browser_wait_for
#   navigation/  → allow:  browser_navigate, browser_navigate_back, browser_click,
#   interaction            browser_type, browser_fill_form, browser_select_option,
#                          browser_hover, browser_drag, browser_drop,
#                          browser_press_key, browser_resize, browser_close
#                  (containment for these lives in --blocked/--allowed-origins,
#                   NOT the hub — the hub can't see the URL inside browser_navigate)
#   touches FS / → prompt: browser_file_upload, browser_handle_dialog,
#   side-effects           browser_pdf_save (if pdf cap enabled)
#   arbitrary    → deny:   browser_evaluate, browser_run_code_unsafe
#   code-exec              (run page/Playwright JS — enable explicitly only if a
#                           workflow truly needs it; default-deny)
```

> **Probe reality check (mirrors graphify's "5 unrecognized reads" note).** The
> `add-server` `classify` heuristic keys on verbs (`read_/list_/get_/search` →
> allow; `create_/write_/run_` → prompt; `delete_/remove_` → deny). Almost none of
> the `browser_*` names match those verbs, so the probe will classify nearly the
> **entire surface as "unrecognized → prompt"** and flag it. That's the safe
> default, but it means the operator **must** curate the tiering above (likely via
> `--configure-perms`) rather than accept the raw proposal — every click prompting
> is unusable, and `browser_evaluate`/`browser_run_code_unsafe` must be pushed from
> the heuristic `prompt` down to `deny`.

For high-security deployments, push navigation/interaction down to `prompt` and
rely on approval-per-action; for the autonomous-browsing use case the user asked
for, keep them `allow` and contain via origins + `--isolated` + `--headless`.

---

## Security posture (browsing the live internet)

This is the riskiest server the hub will host. State the threats plainly:

- **SSRF / internal pivot** — a browser is a perfect SSRF tool; mitigated by the
  seeded `--blocked-origins` (metadata/loopback/RFC1918) and, ideally, an
  `--allowed-origins` allowlist. The hub authz layer **cannot** help here (it gates
  the `browser_navigate` *tool*, not the URL argument) — this is the central reason
  the launch flags matter and the v2 egress-proxy exists.
- **Prompt injection via page content** — a visited page can instruct the agent.
  `--isolated` ensures no credentials/cookies are sitting in the profile for an
  injected instruction to steal; `deny` on `browser_evaluate`/`browser_run_code_unsafe`
  stops a page from coaxing the agent into running attacker JS.
- **Credential/session exfil** — don't persist a logged-in profile unless required;
  if you do (`--storage-state`), treat it as a secret and never log it. The hub's
  secret-redaction result policy still applies to tool output.
- **Local file access** — `--allow-unrestricted-file-access` stays OFF; `file://`
  origins blocked. `browser_file_upload` is `prompt` (it reaches into the FS).
- **Arbitrary code execution** — `browser_evaluate` and `browser_run_code_unsafe`
  are `deny` by default. They are the highest-value targets on this server.
- **Audit** — every browser tool call still flows through the hub's append-only
  audit log; `browser_navigate` calls record the target, giving an after-the-fact
  trail even though pre-call URL gating lives in the server flags.

---

## Testing plan (temp `$UNIFIED_HOME` — never touch real `~/.unified-ai/`)

Build against the real server, document from observed behavior (the `add-server`
methodology).

### Phase 0 — recon (confirm the version-pinned facts)
- Pin a version; confirm: stdio transport, the exact **global bin name**, the
  **license**, that `npx playwright install chromium` is required (navigate fails
  without it), and the live tool list via a raw stdio `list_tools` probe. Capture
  the headed-vs-headless and persistent-vs-isolated defaults firsthand.

### Phase 1 — provisioning + hardened launch
- Run the provisioning block; launch `@playwright/mcp` standalone with the hardened
  flags; confirm `browser_navigate` to a public URL + `browser_snapshot` returns an
  accessibility tree, and that a navigate to `http://169.254.169.254/` /
  `http://localhost/` is **blocked** by `--blocked-origins`.

### Phase 2 — through the hub via `add-server`
- `export UNIFIED_HOME=$(mktemp -d)/unified-ai; uv run unified-mcphub init`.
- `add-server playwright` (pinned npx **and** the rung-4 `--command` bin path);
  observe the probe classifies the surface as mostly `prompt`/unrecognized; curate
  the rule tiers (above) via `--configure-perms`.
- Start the hub; drive the loop through the socket: `browser_navigate` →
  `browser_snapshot` → `browser_click`/`browser_type`. Confirm `browser_evaluate`
  is **denied**, `browser_file_upload` **prompts**, reads are **allowed**, and the
  audit log records each call (esp. the navigate target).
- Repeat the isolation caveat from the graphify spec: a seeded temp-home
  `config.yaml` may still hardcode the real socket/port — rewrite
  `listen.unix_socket` to the temp path + `tcp: null` before `start` so the test
  hub can't clobber a running real hub.

Deliverable: a notes file (provisioning steps + observed bin name/version/license,
the blocked-origin proof, the curated rule set, and the end-to-end through-the-hub
browse loop) — feeds the README.

---

## CI wiring

v1 (config-only, no new package) needs **no new CI job** — there's no Python
package to test, and `ruff … packages` is unaffected. Browser-binary download is
too heavy/flaky to gate every PR on; if any smoke test is added, isolate it behind
a manual/scheduled workflow with `npx playwright install --with-deps chromium`, not
the per-PR `lint-and-test` job. (If Option C lands, add a standalone
`playwright-package` job mirroring the existing `graphify-package (standalone)`
stage, lint covered by the path-based `ruff … packages` already.)

---

## Milestones / phasing

- **v1 (this spec):** config-only integration — provisioning recipe, hardened
  launch profile, curated default-deny rule set, README "Optional servers" row +
  guide. No new code.
- **v1.5 (optional):** thin launcher package `unified-mcp-playwright` (Option C) —
  owns the pin, bakes in hardened flags, ships a `… install` bootstrap subcommand;
  excluded from the uv workspace.
- **v2 (escape hatch):** egress-gating proxy (Option D) for hub-level, audited,
  per-URL allow/deny — only if `--allowed-origins` proves insufficient.

---

## Risks / open points

- **Node + browser binaries are the heavy prereq** — not bundled, not in the
  workspace; provisioning is explicit and opt-in. `preflight()` covers the
  missing-`npx` case; the missing-browser case fails at first `browser_navigate` —
  document the `npx playwright install chromium` step prominently.
- **Per-URL gating is NOT a hub capability** — containment lives in the server's
  `--blocked-origins`/`--allowed-origins`. Bill this honestly; v2 closes it.
- **`browser_evaluate` / `browser_run_code_unsafe`** — arbitrary code execution in
  the page/Playwright; **`deny` by default**, enable only with eyes open.
- **Probe under-classifies** — `browser_*` names don't match the verb heuristic, so
  the operator must curate rules rather than accept the proposal. Documented above.
- **Version churn / pinning** — `@playwright/mcp` ships often; pin
  `@playwright/mcp@<ver>` (rung 2) or pre-install the bin (rung 4). Bare `@latest`
  is refused by `require_pinned_versions`.
- **Persistent-profile concurrency** — one persistent profile can't run twice from
  the same workspace; `--isolated` (the default here) avoids it but loses sessions.
  Note the serialize-on-concurrent-harness behavior.
- **License** — Apache-2.0 observed; **confirm in Phase 0** before any vendoring
  (Option C/v1.5 redistributes nothing — it shells out — so the bar is low, but
  state it).
- **Package symmetry** — v1 ships no `packages/unified-mcp-*` dir, unlike graphify.
  If the team wants every optional server to be a package, promote Option C to v1
  (open decision).
- **Bin-name uncertainty** — `playwright-mcp` vs the older `mcp-server-playwright`;
  resolve in Phase 0 before writing a `--command` entry.
```
