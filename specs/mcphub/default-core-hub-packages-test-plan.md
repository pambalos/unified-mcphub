# Default Core Hub Packages — Live Test Plan

**Status:** ✅ EXECUTED 2026-06-01 — all phases passed; 5 bugs found & fixed during the run (see Results at bottom).

**Target:** a running `unified-mcphub start` with the seeded `default.yaml` (5 servers, `approval.enabled: true`).
**Goal:** exercise every tool, every safety, and the authz/approval/audit/reload seams end-to-end.
**Driver:** the hub is queried over the Unix socket `~/.unified-ai/mcphub/mcphub.sock` via JSON-RPC `POST /mcp`
with header `X-Caller-Id: claude-code` (the same path harnesses + e2e tests use). Wire tool names are
`<server>__<tool>` (e.g. `filesystem__read_file`); the `mcp://server/tool` form is the authz URI.

## How to read this plan

- **Prompt?** column: ✗ = auto-decided (no terminal interaction). ⚠ = blocks on the approval TUI **in your terminal** —
  the row says which key to press to drive the test. Prompt rows are grouped into Phase 4+ so you can watch then.
- Each test lists the **call**, the **expected** result, and a **pass/fail** box to tick.
- Phases 0–3 require **no** interaction; run them first. Phases 4–5 need you at the keyboard. Phase 7 is hot-reload.

---

## Phase 0 — Connectivity & aggregation  (Prompt? ✗)

| # | Call | Expected | ✓ |
|---|---|---|---|
| 0.1 | `initialize` | `result` with serverInfo; status 200 | ☐ |
| 0.2 | `tools/list` | All 5 servers' tools aggregated + namespaced; includes `built-in__ping`. Count = 9 (fs) + 1 (shell) + 2 (fetch) + 2 (python) + 1 (documents) + built-ins | ☐ |
| 0.3 | inspect `tools/list` schemas | `fetch__fetch_webpage` exposes `allow_blocked`; `filesystem__edit_file` exposes `replace_all`; params trimmed (no `file_content`/`auto_fuzzy`) | ☐ |
| 0.4 | `built-in__ping` | `success`/pong | ☐ |

## Phase 1 — Read & safe tools (auto-allow)  (Prompt? ✗)

Authz: `read_*`/`list_*`/`get_*` wildcards + explicit allows. None should prompt.

| # | Call | Expected | ✓ |
|---|---|---|---|
| 1.1 | `filesystem__list_files` `{path: "<repo>"}` | `success:true`, file/dir entries, hidden filtered | ☐ |
| 1.2 | `filesystem__file_info` `{path: "<a file>"}` | size, line_count, type, modified | ☐ |
| 1.3 | `filesystem__read_file` `{path, start_line:1, end_line:5}` | line-numbered `content` (`1→…`), `total_lines` | ☐ |
| 1.4 | `filesystem__read_file` `{path, offset:0, limit:20}` | `mode:"byte"`, 20 bytes, `is_text` | ☐ |
| 1.5 | `filesystem__glob_files` `{pattern:"**/*.py", directory:"<repo>"}` | matches with rel paths, `is_file` | ☐ |
| 1.6 | `filesystem__search_files` `{query:"def main", path:"<repo>"}` | grep-like results; **`engine:"ripgrep"`** (rg present) | ☐ |
| 1.7 | `filesystem__find_files` `{pattern:"*.md", content:"hub", directory:"<repo>"}` | hybrid: `strategy:"hybrid_glob_then_content"`, per-file `content_matches` | ☐ |
| 1.8 | `python__check_syntax` `{path:"<a .py>"}` | `valid:true`, `lines` | ☐ |
| 1.9 | `python__find_function` `{name:"main", directory:"<repo>"}` | matches with `signature`, `type`, `line` | ☐ |
| 1.10 | `documents__read_document` `{path:"README.md"}` | `success`, `format:"md"`, `content` | ☐ |
| 1.11 | `fetch__search_internet` `{query:"model context protocol", count:5}` | `success`, `backend:"duckduckgo"` (no BRAVE_API_KEY), ≤5 results | ☐ |
| 1.12 | `fetch__fetch_webpage` `{url:"https://example.com"}` | `success`, `title:"Example Domain"`, text | ☐ |

## Phase 2 — Path-safety & input validation (auto-decided)  (Prompt? ✗)

| # | Call | Expected | ✓ |
|---|---|---|---|
| 2.1 | `filesystem__read_file` `{path:"/etc/shadow"}` | `success:false`, "restricted by … safety blocklist" | ☐ |
| 2.2 | `filesystem__file_info` `{path:"~/.ssh/id_rsa"}` | `success:false`, restricted | ☐ |
| 2.3 | `python__check_syntax` `{path:"/etc/hosts"}` | `success:false`, "not a .py file" | ☐ |
| 2.4 | `filesystem__read_file` `{path:"/nope/missing"}` | `success:false`, "not a file" | ☐ |
| 2.5 | `documents__read_document` `{path:"<a .xyz>"}` | `success:false`, "unsupported format" | ☐ |
| 2.6 | `tools/call` unknown tool `nope__nope` | JSON-RPC error / unknown server (authz default-deny) | ☐ |

## Phase 3 — fetch SSRF (auto-decided; one prompt at 3.4)  (Prompt? mostly ✗)

| # | Call | Expected | Prompt? | ✓ |
|---|---|---|---|---|
| 3.1 | `fetch__fetch_webpage` `{url:"http://localhost:<your-port>"}` | **allowed silently**; success or connection error — but NOT "blocked_host" | ✗ | ☐ |
| 3.2 | `fetch__fetch_webpage` `{url:"http://169.254.169.254/latest/meta-data/"}` | `success:false`, `error:"blocked_host"`, hint mentions `allow_blocked` | ✗ (authz allows, server refuses) | ☐ |
| 3.3 | `fetch__fetch_webpage` `{url:"file:///etc/passwd"}` | `success:false`, "only http/https" | ✗ | ☐ |
| 3.4 | `fetch__fetch_webpage` `{url:"http://169.254.169.254/…", allow_blocked:true}` | **TUI prompt fires with warning** → press **`d` (deny)** → call returns denied/`no` | ⚠ press `d` | ☐ |
| 3.5 | repeat 3.4 → press **`a` (allow once)** | server then attempts fetch (likely connection timeout off-cloud) — proves the override path works end-to-end | ⚠ press `a` | ☐ |

> 3.2 vs 3.4 is the crux: a blocked host with no override is refused *by the server* (no prompt); adding
> `allow_blocked:true` makes *authz* prompt before the server is ever reached.

## Phase 4 — Writes & exec (every call prompts)  (Prompt? ⚠)

Watch the terminal; each row says the key to press. Tests both the **allow** and **deny** branches.

| # | Call | Key | Expected | ✓ |
|---|---|---|---|---|
| 4.1 | `filesystem__create_file` `{path:"/tmp/uhub-test/a.txt", content:"hello"}` | `a` | prompt → allow → file created, `success` | ☐ |
| 4.2 | `filesystem__create_file` (same path again) | (no prompt — fails first) | `success:false`, "already exists" (refuses overwrite *before* authz? no — authz prompts, then server refuses) → so prompt fires, press `a`, then server returns exists-error | ☐ |
| 4.3 | `filesystem__edit_file` `{path:"/tmp/uhub-test/a.txt", old_string:"hello", new_string:"world"}` | `a` | prompt → allow → `replacements:1`; file now "world" | ☐ |
| 4.4 | `filesystem__edit_file` ambiguous (create file "x\nx", replace "x") | `a` | prompt → allow → `success:false`, `occurrences:2` (needs replace_all) | ☐ |
| 4.5 | `filesystem__edit_file` `{…, replace_all:true}` | `a` | prompt → allow → `replacements:2` | ☐ |
| 4.6 | `filesystem__delete_file` `{path:"/tmp/uhub-test/a.txt"}` | `a` | prompt → allow → `mode:"soft"`, `trashed_to: ~/.unified-ai/mcphub/trash/…` ; file gone, trash copy exists | ☐ |
| 4.7 | `filesystem__delete_file` (a fresh file) | `d` | prompt → **deny** → call denied, file still present (proves deny branch) | ☐ |
| 4.8 | `shell__execute_command` `{command:"echo hi && pwd"}` | `a` | prompt → allow → `exit_code:0`, stdout has "hi" | ☐ |
| 4.9 | `shell__execute_command` `{command:"sleep 3", timeout:1}` | `a` | prompt → allow → `timed_out:true`, `success:false` | ☐ |
| 4.10 | `shell__execute_command` `{command:"exit 7"}` | `a` | prompt → allow → `exit_code:7`, `success:false` | ☐ |

### 4b — `allow_always` writes a persistent rule

| # | Call | Key | Expected | ✓ |
|---|---|---|---|---|
| 4.11 | `filesystem__create_file` `{path:"/tmp/uhub-test/b.txt", …}` | `A` (allow_always) | prompt → allow_always → file created | ☐ |
| 4.12 | `filesystem__create_file` `{path:"/tmp/uhub-test/c.txt", …}` | (none) | **no prompt** — auto-allowed by the new tier-1 rule | ☐ |
| 4.13 | inspect `~/.unified-ai/mcphub/workspaces/default.yaml` | a new exact `create_file` allow rule for caller `claude-code` was prepended | ☐ |

## Phase 5 — Dangerous-commands floor  (Prompt? ⚠)

The floor forces `prompt` independent of the workspace rules.

| # | Call | Key | Expected | ✓ |
|---|---|---|---|---|
| 5.1 | `shell__execute_command` `{command:"rm -rf /tmp/uhub-test/nope"}` | `d` | prompt sourced from **danger_floor** (not the plain exec rule) → deny | ☐ |
| 5.2 | `shell__execute_command` `{command:"sudo whoami"}` | `d` | floor match → prompt → deny | ☐ |

## Phase 6 — Audit verification  (Prompt? ✗)

| # | Action | Expected | ✓ |
|---|---|---|---|
| 6.1 | `unified-mcphub audit tail` (or read `~/.unified-ai/mcphub/audit/…`) | every call above has paired received+completed entries by `request_id` | ☐ |
| 6.2 | check a read call | `authz_decision:"allow"`, `source:"wildcard"`/`"exact"` | ☐ |
| 6.3 | check 4.7 (denied delete) | `authz_decision` reflects deny; no tool side-effect | ☐ |
| 6.4 | check 3.4 (override prompt) | records the prompt + the `allow_blocked` arg | ☐ |

## Phase 7 — Hot reload (live config change)  (Prompt? ✗)

| # | Action | Expected | ✓ |
|---|---|---|---|
| 7.1 | edit `~/.unified-ai/mcphub/workspaces/default.yaml`: set `fetch.enabled: false`; save | within ~1s hub logs reload; `fetch__*` tools disappear from `tools/list`; the fetch subprocess is torn down | ☐ |
| 7.2 | revert (`enabled: true`); save | fetch server re-spawns; tools reappear | ☐ |
| 7.3 | add an authz `prompt` rule for `mcp://filesystem/read_file`; save → call `read_file` | now prompts (proves rule hot-applies) — press `a` | ☐ |
| 7.4 | break the YAML (bad indent); save | hub logs "reload failed; keeping prior config"; keeps serving old config (no crash) | ☐ |

## Phase 8 — Search-engine fallback (optional)  (Prompt? ✗)

| # | Action | Expected | ✓ |
|---|---|---|---|
| 8.1 | `filesystem__search_files` with `rg` on PATH | `engine:"ripgrep"` (Phase 1.6 already covers) | ☐ |
| 8.2 | (optional) start a fetch/fs server with PATH lacking `rg` | `engine:"stdlib"`, same result shape | ☐ |

---

## Pass criteria

- All 5 servers aggregate; every tool returns its documented shape.
- Reads auto-allow; writes/exec/override prompt; unknown tools default-deny.
- Path-safety blocks restricted paths; SSRF refuses metadata without override and prompts with it.
- Soft-delete trashes; hard-delete (config) unlinks; ambiguous edit refuses.
- `allow_always` persists a rule; audit pairs every call with the right decision.
- Hot reload applies enable/disable + rule edits live and survives bad YAML.

---

## Results — executed 2026-06-01 (all phases ✅)

Driven over the Unix socket as `claude-code`; interactive prompts answered in the hub terminal.

### Approval decision matrix (ADR-0018) — all five exercised

| Key | Decision | Test | Observed |
|---|---|---|---|
| `a` | allow once | 4.1/4.3/4.8 | allowed; no rule written |
| `s` | allow_session | Test S (shell exec ×2) | 1st prompted→allow; **2nd auto-allowed, no prompt**; file unchanged (in-memory until restart) |
| `A` | allow_always | 4.11/4.12 | allowed; **tier-1 allow rule persisted**; next call auto-allowed |
| `d` | deny once | 3.4/4.7 | `prompt_denied`; no side-effect; no rule written |
| `D` | deny_always | Test D (delete ×2) | 1st `prompt_denied`; **deny rule persisted**; 2nd `deny` with **no prompt**; files survive |

### Bugs found by live testing — all fixed + regression-tested

1. `find_files` hybrid returned 0 under the **stdlib** engine (`os.walk` on a file path) → file-aware scan.
2. `find_files` mis-parsed under the **ripgrep** engine (single-file output omits the filename; colon-in-match) → `--with-filename` + defensive parse.
3. **DuckDuckGo** `html` endpoint bot-blocked **and** falsely reported `success:true` → switched to the `lite` endpoint + honest `success:false` on block.
4. **Dangerous-commands floor was dead for shell** (`mcp://shell/exec:*` vs the real tool `execute_command`) — `rm -rf`/`sudo` ran unprompted under a catch-all allow → patterns aligned to `execute_command` + regression test.
5. `allow_always`/`deny_always` rewrote the workspace YAML via PyYAML `safe_dump`, **stripping all comments** → persist path switched to `ruamel.yaml` round-trip (comments/order/format preserved); verified live on a real `deny_always`.

### Config decisions made during the run

- `built-in__ping` was default-denied (correct default-deny; no seeded rule) → **allowlisted** in both the packaged seed and live workspace.
- Shell tool name **kept as `execute_command`** (accurate: server runs `/bin/sh` via `shell=True`, so `bash` would be misleading; orchestrator-faithful).
- ripgrep is opportunistic (Option A): real `rg` when present (now installed), stdlib fallback otherwise — both engines validated.

### Notes / minor

- The hub does **not** hot-reload `dangerous-commands.yaml` (only `config.yaml` + the active workspace) — floor edits need a restart.
- `allow_session` state is in-memory and clears on restart (not on config reload).
