# Plan — `add-server` / `remove-server` CLI + server-memory worked example

Status: **proposed** · Target milestone: M0.75 · Owner: TBD

Goal: give operators a guided, one-command way to add an external MCP server to a
workspace — write the `servers:` entry, **probe the live server to propose authz
rules**, and persist both while preserving the hand-curated comments in the
workspace YAML. Ship `server-memory` as the tested worked example, rewrite the
README into a real "Adding MCP servers" guide, fix the inaccurate seed claim, and
make Python 3.12 the floor.

---

## Locked decisions

1. **Comment-preserving writes via `ruamel.yaml`** (round-trip). Added as a
   dependency to `unified-mcphub` only. `pyyaml` stays for runtime load.
2. **Probe is on by default.** `add-server` connects to the server once, lists
   tools, classifies them, and proposes rules. `--no-probe` skips it.
3. **Scope = `add-server` + `remove-server` + `--npx` / `--uvx` shorthands.**
   Shorthands are documented *conveniences*; generic `--command/--arg` is the
   blessed primary path (see Supply-chain posture below).
4. **Python 3.12 is the floor.** `requires-python = ">=3.12"`, ruff/mypy targets
   → `py312`, across all three packages.
5. **`require_pinned_versions` policy, default on** (hub-global safety layer).
   Blocks unpinned fetch-and-run upstreams (`npx -y pkg`, bare `uvx pkg`). See
   Supply-chain posture below.

---

## Supply-chain posture (the npx/uvx fetch-and-run problem)

`npx -y <pkg>` / `uvx <pkg>` **download and execute remote code at process
spawn** — upstream of the hub's call-time gating (default-deny, approval, audit).
So a naively-added shorthand server quietly punches a hole in the exact posture
the product sells. We address it on three fronts: framing, a default-on policy,
and a documented hardening ladder.

### The hardening ladder (document; don't pretend rung 2 is the top)

1. **Unpinned `@latest`** — worst; banned by default via `require_pinned_versions`.
2. **Pinned version** (`pkg@1.2.3`, `pkg==1.2.3`) — **drift guard**: no silent
   pickup of a freshly-published / hijacked `@latest`. Still fetches-and-runs;
   does **not** protect against a malicious pinned package. This is what
   `require_pinned_versions` enforces — necessary, not sufficient.
3. **Integrity/hash pinning** — pin the exact artifact hash, not just the version
   string; defeats artifact-swap. Documented as hardening.
4. **Pre-install + point at the binary** (`uv tool install` / `npm i -g`, then
   `--command <binary>`) — **no network at spawn**, fully auditable. The gold
   standard; recommended for the security-conscious.

`require_pinned_versions` lands at rung 2 and is correct as the *default*; the
README must bill it honestly as a drift guard, not "secure," and point rungs 3–4
as the path to actually closing fetch-and-run.

### Consistency with image-digest pinning

This is the stdio analog of the container policy already planned in `sandbox.py`
("image-digest pinning + Sigstore" — images pinned by `sha256:` digest, not a
mutable tag). Frame both as **one "pin your upstreams" policy** spanning packages
+ images, not a bolt-on.

### Policy mechanics

- **Config:** `require_pinned_versions: true` on `HubConfig` (the hub-global
  safety layer, beside default-deny / dangerous-commands). Default **on**.
- **Per-server escape hatch:** `allow_unpinned: true` on `ServerSpec` — explicit
  and audited, mirroring the existing `allow_blocked` fetch override. For servers
  that genuinely only ship `@latest` or a git ref.
- **Two enforcement points:**
  - **`add-server` time** — refuse to write an unpinned shorthand; emit a clear
    fix (*"… has no version; pin it (`@2025.4.x`) or pass `--allow-unpinned`"*).
    Trivial to detect since we control shorthand expansion.
  - **config load / reload** — best-effort lint over `command/args`: refuse (or
    loudly warn) to **start** an unpinned `npx`/`uvx` upstream, so a hand-edited
    workspace can't bypass the policy. Stronger guarantee given the hub's posture.
- **Detection caveat (state plainly):** "is this pinned?" is a heuristic over
  `command/args` — `pkg@x.y.z` (npm), `pkg==x.y.z` (uv/pip). Reliable for
  shorthands (we build the args); best-effort for raw `--command`. Not airtight.
- **Preflight:** when a shorthand resolves to fetch-and-run, `add-server` prints a
  one-line note recommending pre-install (rung 4) or a pinned hash (rung 3).

---

## Order of attack — test first, document from reality

Build against a real server so the CLI, the probe heuristics, and the docs all
match observed behavior.

### Phase 0 — reconnaissance (temp `$UNIFIED_HOME`)

Never touch the operator's real `~/.unified-ai/`. All testing runs under an
isolated home:

```sh
export UNIFIED_HOME=$(mktemp -d)/unified-ai
uv run unified-mcphub init
```

Wire `server-memory` **by hand first** (to learn the exact entry + the rules it
needs) before automating it:

```yaml
# workspaces/default.yaml — append under servers:
memory:
  enabled: true
  upstream:
    command: npx
    # Pin the version — require_pinned_versions (default on) refuses an unpinned
    # fetch-and-run upstream at load. Use the real published version when testing.
    args: ["-y", "@modelcontextprotocol/server-memory@<pinned>"]
    env: { MEMORY_FILE_PATH: "/tmp/mcphub-memory-test/memory.json" }
```

Observe via `list-servers`, `list-tools`, `audit tail`. Confirm the **read/write
split**: `read_graph` / `search_nodes` / `open_nodes` are already allowed by the
seed `mcp://*/read_*` etc. wildcards, while `create_entities` / `add_observations`
/ `delete_*` fall through to **default-deny** (NOT prompt). That gap is the whole
reason `add-server` proposes rules. Capture real gotchas: npx PATH resolution
(`supervisor.py` only rewrites bare `python`, so `npx` must be on PATH), first-run
npx download latency vs. the supervisor's `wait_ready` timeout (30s).

Deliverable: a short notes file feeding Phase 2's heuristics + the README.

### Phase 1 — config model + `servers.py` module

**Config model** (`config.py`): add `require_pinned_versions: bool = True` to
`HubConfig`; add `allow_unpinned: bool = False` to `ServerSpec`. Update
`defaults/config.yaml` with the new field + a comment. The load-time pinning lint
lives in `hub._reload` / startup (refuse-or-warn on an unpinned upstream lacking
`allow_unpinned`), reusing `servers.is_pinned`.

New `packages/unified-mcphub/src/unified_mcphub/servers.py`, mirroring the
`installers/` dispatch style.

- `build_spec(...) -> ServerSpec` — turn CLI args into a validated `ServerSpec`
  (reuses `config.Upstream` / `ServerSpec`). Shorthand expansion:
  - `--npx PKG [--arg …]` → `command: npx`, `args: ["-y", PKG, …extra]`
  - `--uvx PKG [--arg …]` → `command: uvx`, `args: [PKG, …extra]`
  - `--command CMD --arg …` → raw stdio
  - `--url URL [--auth-secret-ref NAME]` → remote HTTP
  - `--env K=V` (repeatable), `--disabled`, `--allow-unpinned` (writes
    `allow_unpinned: true` on the server + skips the pinning refusal)
- `is_pinned(spec) -> bool` — heuristic over `command/args`: detects a version
  spec for npx (`pkg@x.y.z`, `@scope/pkg@x.y.z`) and uv/pip (`pkg==x.y.z`,
  `pkg@<gitref>`). Used by both the `add-server` refusal and the config-load lint.
  Returns `True` (skip enforcement) for non-fetch commands and for `url:`/`image:`
  upstreams. Reliable for shorthands, best-effort for raw `--command`.
- `preflight(spec)` — **deterministic PATH check, runs before anything else.**
  Resolve the upstream command via `shutil.which` (`npx` / `uvx` / a raw
  `--command`; `python`→hub interpreter is always present; `url:` upstreams are
  skipped). If it's absent → **hard error** with an install hint (`"npx not on
  PATH — install Node, or use --command <abs-path>"`), not a warning, since the
  server cannot run without it. `--no-preflight` to override for unusual setups.
- `probe(spec) -> list[types.Tool]` — connect using the shared client
  (`StdioConnection`/`HttpConnection` + `list_tools()`), same pattern as
  `supervisor.py:79`. **No race with first-run downloads** — handled as two
  deterministic steps:
  1. **Warm-up** — explicitly fetch/stand up the package to completion before
     probing (`npx`/`uvx` cache after first fetch: `~/.npm/_npx`, the uv cache).
     This step is *awaited*, shows a progress spinner ("fetching <pkg>…"), and is
     bounded only by a generous, configurable `--probe-timeout` (default 120s) —
     **decoupled from the supervisor's 30s `wait_ready`**, which only ever sees a
     warm cache afterward.
  2. **Probe** — `list_tools()` against the now-warm server under a short,
     normal timeout. The cold-download cost is paid in step 1, so this never
     times out on a fresh package.
  Returns `[]` on failure (caller warns and falls back to a scaffold).
- `classify(tool_name) -> "allow" | "prompt" | "deny"` — name heuristic, **three
  tiers** (fail-closed on destructive ops):
  - reads → `allow`: `read_*`, `list_*`, `get_*`, `search*`, `find*`, `query*`,
    `fetch*` (read variants)
  - destructive ops → `deny`: `delete_*`, `remove_*`, `drop_*`, `destroy_*` (a
    destructive tool is never silently reachable; the operator opts in explicitly
    via `--configure-perms` or by hand-editing the rule to `prompt`/`allow`).
  - other mutations → `prompt`: `create*`, `add*`, `update*`, `edit*`, `write*`,
    `set*`, `execute*`, `run*`
  - unrecognized → `prompt` (safe default), flagged in the printed summary so the
    operator sees what wasn't auto-classified (e.g. graphify's `shortest_path`).
  Rules are written **server-scoped** (`mcp://NAME/<tool>`) so the workspace stays
  self-documenting rather than leaning on global wildcards.
- `write_workspace(name, spec, rules, *, dry_run, force)` — **ruamel round-trip**:
  load the workspace file preserving comments, insert/replace the server under
  `servers:` and append rules under `authz.rules:`, then write back via
  `util.secure_write` (0600). `--dry-run` prints the unified diff and writes
  nothing. `--force` overwrites an existing entry; without it, a name collision
  errors.
- `remove_server(name, server)` — round-trip delete of the `servers:` entry and
  **all rules scoped specifically to it** (rules whose `tool` pattern's server
  segment is exactly `server`, i.e. `mcp://server/...` — *not* shared wildcards
  like `mcp://*/read_*`, which belong to every server and must stay). Default
  flow: collect the entry + its N scoped rules, **prompt** "remove server
  '<server>' and its N rule(s)? [y/N]", and remove the whole set on yes; `--yes`
  skips the prompt. Removal is deterministic (exact server-segment match), so no
  heuristic guessing. Any rule that references the server only via a shared
  wildcard is left untouched and noted in the output.

Interactive flow (default): print proposed rules, ask to confirm. `--yes` makes
it non-interactive for CI/scripts.

`--configure-perms` — opt-in per-tool wizard. After the probe, step through each
discovered tool in a rich prompt showing the heuristic default, and read the
operator's choice: `a`llow / `p`rompt / `d`eny, with **empty/Enter accepting the
shown default**. Produces the same server-scoped rules, just operator-decided
rather than heuristic. No-op (falls back to the plain confirm flow) under
`--yes`, `--no-probe`, or when the probe returns no tools. Reuse the `rich`
prompts already in `approval.py` rather than a second TUI stack.

### Phase 2 — CLI wiring

In `cli.py`, add `cmd_add_server` / `cmd_remove_server` and subparsers matching
the surface above. `add-server` enforces `require_pinned_versions`: an unpinned
shorthand without `--allow-unpinned` is refused with the fix message; on a
fetch-and-run shorthand it also prints the preflight note (recommend rung 3/4);
`preflight()` hard-errors first if the runtime (`npx`/`uvx`/`--command`) is absent
from PATH (`--no-preflight` overrides). Reload is automatic — the
hub's file-watcher (`hub._watch_reload`) picks up the workspace change live; print
a reminder that a running hub applies it within a moment, and that writes now
require approval per the new `prompt` rules.

### Phase 3 — tests (CI gates on ruff format + ruff check + pytest)

- **unit** (`tests/unit/test_add_server.py`): shorthand expansion → `ServerSpec`;
  `classify` table (destructive `delete_*`/`remove_*`/`drop_*`/`destroy_*` →
  `deny`); `--configure-perms` accepts
  per-tool overrides and Enter-keeps-default (driven via a scripted input
  stream); `is_pinned` table (npm `@x.y.z`, uv `==x.y.z`, unpinned,
  non-fetch commands, url/image); pinning refusal at `add-server` + `--allow-unpinned`
  bypass; ruamel round-trip preserves comments + ordering; `--dry-run`
  writes nothing; collision without `--force` errors; `preflight` hard-errors on
  a missing-from-PATH command and `--no-preflight` bypasses; `remove-server`
  deletes entry + exactly-scoped rules after `[y/N]`/`--yes` while leaving shared
  wildcards (and noting them).
- **policy** (`tests/unit/test_pinning.py`): config-load lint refuses/warns on an
  unpinned `npx`/`uvx` upstream lacking `allow_unpinned`; `require_pinned_versions:
  false` disables it; `allow_unpinned: true` per-server bypasses it.
- **e2e** (`tests/e2e/test_m0_add_server.py`): run `add-server` against the
  existing `tests/fixtures/fake_mcp_server.py` → probe lists its tools → rules
  generated → workspace file updated → start hub → confirm the new tool is
  callable / denied per the generated policy.

### Phase 4 — docs + claim fix + python floor

- **README rewrite** (`packages/unified-mcphub/README.md`): turn "Workspaces &
  config" into **"Adding MCP servers"** — the `add-server` happy path first
  (with the tested `memory` example end-to-end), then the manual-YAML route,
  the workspace anatomy, the **authz-rules-are-mandatory / writes-are-denied**
  warning, secrets + OAuth, hot-reload, and the `list-servers`/`list-tools`/
  `audit tail` verify loop. Mirror a short version into the repo-root README.
  Required new README subsections:
  - **"Distribution methods"** — npx / uvx / docker (M0.5) / remote URL, with the
    standard config shapes; note `--command` is primary and shorthands are sugar.
  - **"Supply chain & version pinning"** — the fetch-and-run risk in plain terms,
    the hardening ladder (rungs 1–4), `require_pinned_versions` billed honestly as
    a *drift guard* (default on, `allow_unpinned` escape hatch), and the
    pre-install/point-at-binary recommendation as the way to actually avoid
    fetch-and-run. Cross-reference image-digest pinning as the same policy for
    containers.
- **Fix the inaccurate claim** (package README ~line 88: "ships with commented
  examples for stdio `command:` and HTTP `url:` upstreams") — either correct the
  sentence or, better, **add the missing commented stdio + HTTP server templates
  to `defaults/default.yaml`** so seed and docs agree.
- **Python 3.12 floor**: bump `requires-python = ">=3.12"` in all three
  `pyproject.toml`; set ruff `target-version = "py312"` and mypy
  `python_version = "3.12"`. CI already runs 3.12 — this just makes the declared
  floor match what's actually tested (closes the untested-3.10-promise gap).

---

## Follow-on additions (from remote-server testing — implemented)

Validated `--url` against live remote servers (Hugging Face, end-to-end through the
hub: probe authenticated + runtime `hf_whoami`). That surfaced three additions, all
now implemented:

1. **Trailing read verbs.** Real servers often name tools `<noun>_<verb>`
   (`hub_repo_search`, `hf_doc_fetch`). `classify`/`is_recognized` now match a verb
   at the **leading OR trailing** word boundary (snake suffix), destructive still
   winning, so suffix-style reads get `allow` instead of all-`prompt`.
   `findings_purge` still matches nothing. `generate` added to mutate.
2. **Custom auth header.** `ServerSpec.auth_header` (default `Authorization`) +
   `auth_scheme` (default `Bearer`, `null` = raw value). `build_connection` uses
   them; CLI `--auth-header` / `--auth-scheme ''`. Unlocks API-key servers like
   Context7 (`CONTEXT7_API_KEY: <key>`); defaults still give HF-style bearer.
3. **OAuth Dynamic Client Registration.** `OAuthConfig` allows an `issuer`
   (endpoints discovered via RFC 8414) and registers a public PKCE client (RFC 7591)
   on first `auth login`, caching the `client_id`. Needed because modern remote
   servers (Linear) are DCR-first. `oauth.build_flow` resolves static-or-DCR;
   `cmd_auth` uses it. Live browser-flow test against Linear is manual (post-merge).

Shared-builder note: `_probe_connection` delegates to `supervisor.build_connection`
(single source of truth), so the probe authenticates exactly as the hub will run it.

## Risks / open points

- **npx/uvx must be on PATH** for shorthand servers; `supervisor._make_connection`
  only rewrites bare `python`. **Resolved:** `preflight()` hard-errors with an
  install hint when the command isn't on PATH (`--no-preflight` to override).
- **Probe vs. first-run npx/uvx download.** **Resolved:** deterministic warm-up
  step (awaited fetch, progress spinner, generous `--probe-timeout`) precedes the
  short-timeout `list_tools` probe, so there's no race and no dependence on the
  supervisor's 30s `wait_ready`.
- **ruamel formatting drift** — pin behavior with a golden-file round-trip test so
  future ruamel upgrades don't silently reflow the seed workspace.
- **`remove-server` rule cleanup.** **Resolved:** delete the entry + all
  exactly-server-scoped rules (`mcp://NAME/...`) deterministically after a `[y/N]`
  prompt (`--yes` to skip); shared wildcard rules are left and noted. No
  heuristic deletion.
