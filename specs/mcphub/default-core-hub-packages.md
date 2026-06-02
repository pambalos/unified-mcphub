# Default Core Hub Packages — light/safe tier (spec, for review)

**Status:** Draft for review (2026-05-29)
**Parent:** [m0.v1.md §10](m0.v1.md) (hub-as-MCP-server), [ADR-0023](../../docs/adrs/0023-mcp-client-shared-package.md) (narrow waist), [ADR-0006](../../docs/adrs/0006-mcp-hub-authz.md) (authz), [ADR-0018](../../docs/adrs/0018-interactive-authz-prompts.md) (approval)

## Goal

Ship a usable set of tools **out of the box** so a fresh `unified-mcphub start` has more than
`built-in__ping`. This tier rebuilds the orchestrator's **light/safe** tool packages
(`filesystem`, `shell`, `internet`, `python_tools`, `documents`) as first-party **stdio MCP
servers** and bundles them as the hub's default.

## Why rebuild instead of import

The orchestrator's tools **cannot be imported lightweight**: `unified_orchestrator/__init__.py`
imports `Agent` (and patches httpx "before any LLM SDK import"), so importing *any*
`unified_orchestrator.tools.*` drags anthropic/openai/whisper/pyaudio. The tools are also coupled
to `ToolDefinition` (the agent-runtime type the hub deliberately doesn't speak — ADR-0023's waist
is `mcp.types.Tool`). So migration goes **through MCP**: clean stdio servers, stdlib-only logic,
**no orchestrator import**. (This is the `mcp-a2a-integration.md` MCP-WRAP plan, minus containers.)

## Package + wiring

- New package `packages/unified-mcp-servers/` — **deps: `mcp` only**. One stdio server per module,
  runnable as `python -m unified_mcp_servers.<name>`; `mcp.run()` (FastMCP) stdio transport.
- The **hub depends on it** (workspace source), so it's importable by the hub's interpreter.
- **Spawn wiring:** the seeded `default.yaml` references each server as
  `command: python`, `args: ["-m", "unified_mcp_servers.<name>", <flags>]`. The hub's supervisor
  resolves `command` `python`/`python3` → `sys.executable` (the hub's venv interpreter, which has
  the package). No PATH/activation assumptions.
- **Per-server enable/disable:** `ServerSpec` gains `enabled: bool = true`; the hub skips
  `enabled: false` servers (start + reload diff). All five seeded with `enabled: true`; flip to
  `false` to disable a package without deleting its entry.
- **Per-server config** is passed as server flags in the workspace yaml `args` (or `env`), e.g.
  `unified_mcp_servers.filesystem --delete-mode hard`. See "Configuration toggles" below.
- **The hub is the security layer.** authz (ADR-0006) + the `dangerous-commands.yaml` floor +
  approval TUI (ADR-0018) gate every call. Servers therefore do **not** re-implement command
  denylists or approval prompts (see "Safeties dropped").

## Servers & tools (rebuilt surface)

Faithful to the orchestrator tool names; params trimmed to the canonical set (silent LLM-alias
params dropped). All return a JSON object `{ "success": bool, ... }`.

> **Search engine (resolved):** `search_files`/`find_files` use the real `rg`
> binary when it is on PATH (faithful + fast + gitignore-aware) and fall back to
> a stdlib `os.walk`+`re` scan when it is absent — so the package stays
> `mcp`-only with no install-time binary requirement (Option A).

### `mcp://filesystem/*`
| Tool | Params | Returns | Notes vs orchestrator |
|---|---|---|---|
| `file_info` | `path` | size, line_count, type, mtime | as-is |
| `read_file` | `path`, `start_line?`, `end_line?`, `offset?`, `limit?` | line-numbered `content`, `lines` | as-is |
| `create_file` | `path`, `content` | `path` | **drop** silent aliases `file_content`/`text` |
| `edit_file` | `path`, `old_string`, `new_string`, `replace_all=false` | `replacements` | **drop** silent aliases `original_text`/`new_text` |
| `list_files` | `path="."`, `file_pattern="*"`, `recursive=false`, `show_hidden=false` | entries | as-is |
| `delete_file` | `path` | `trashed_to` / `deleted` | **soft delete** by default → moves to `~/.unified-ai/mcphub/trash/<ts>-<name>`; `delete-mode: hard` (config) switches to `unlink`. Floor-gated (`delete_*`). |
| `search_files` | `query`, `path?`, `file_pattern="*"` | matches (grep-like) | as-is |
| `glob_files` | `pattern`, `directory?`, `case_sensitive=false` | paths | **drop** `auto_fuzzy` (agent-ergonomic) |
| `find_files` | `pattern?`, `content?`, `directory="."`, `case_sensitive=false` | paths | **drop** the no-op `recursive` compat arg |

**Dropped tool:** `resolve_path` (fuzzy-path resolver — an orchestrator agent ergonomic, not useful standalone).

### `mcp://shell/*`
| Tool | Params | Returns | Notes |
|---|---|---|---|
| `execute_command` | `command`, `working_directory="."`, `timeout=30` | exit_code, stdout, stderr, duration | **drop** `allow_dangerous`, `capture_output` (always on), `confirmation_callback`, command-chain pre-validation, and the in-tool denylists (see below) |

### `mcp://fetch/*`
| Tool | Params | Returns | Notes |
|---|---|---|---|
| `fetch_webpage` | `url`, `max_chars=50000`, `allow_blocked=false` | text, title, status | stdlib `urllib`. **SSRF guard default-OFF** (matches the ecosystem norm — localhost/private/LAN fetches just work, no flag, no prompt). The only refusal is a single configurable `blocked_hosts` list (`--block-host HOST\|IP\|CIDR`, repeatable), seeded by `default.yaml` with the cloud-metadata addresses. A blocked host is reachable per-call with `allow_blocked=true`, which the hub is seeded to **prompt** on (warning shown) — explicit + audited. No separate allowlist and no broad private-range guard at M0 (see Decision 2). |
| `search_internet` | `query`, `count=10` | results | **Pluggable backend** (config `search-backend`, default `auto`): `auto` (Brave if `BRAVE_API_KEY` set, else DuckDuckGo) \| `duckduckgo` (free, zero-config, fragile HTML scrape) \| `brave` (`BRAVE_API_KEY`) \| `none`. SearXNG moved to the container tier (see Out of scope). |

**Deferred (not in first cut):** `fetch_webpage_sections`, `extract_webpage_content` (secondary; add if wanted).

### `mcp://python/*`  (static analysis only — no code execution)
| Tool | Params | Returns | Notes |
|---|---|---|---|
| `check_syntax` | `path` | valid, errors | `ast.parse`; read-only |
| `find_function` | `name`, `directory="."`, `type="any"`, `exact_match=false` | matches | `ast` walk; read-only |

### `mcp://documents/*`
| Tool | Params | Returns | Notes |
|---|---|---|---|
| `read_document` | `path` | text, format | text formats via stdlib; **PDF/DOCX lazy-import** `pypdf`/`python-docx` and return a "pip install …" error if absent — keeps the server light |

## Safeties / validations being DROPPED or CHANGED (review focus)

The orchestrator tools carried their own security because they ran *inside* an autonomous agent
with no external gate. In the hub, the gate is external and authoritative, so we remove the
in-tool layer to avoid a second, divergent denylist (the leaky-blacklist anti-pattern ADR-0006
explicitly moved away from).

| Orchestrator safety | Action | Why |
|---|---|---|
| **shell denylists** — `DANGEROUS_COMMANDS` (`rm -rf`, `dd`, `mkfs`, fork-bombs…), `DANGEROUS_PATTERNS`, `RESTRICTED_COMMANDS` (`sudo`, `su`, `systemctl`…) | **DROP** | The hub's `dangerous-commands.yaml` floor already covers these (`rm -rf*`, `sudo*`, …) and forces approval; default-deny authz governs the rest. Two denylists = drift + DRY violation. Single source = the floor. |
| **shell `confirmation_callback` / `allow_dangerous` / `check_dangerous_command`** | **DROP** | Approval is the hub's in-process TUI (ADR-0018), keyed off the floor. A server-side prompt is the wrong layer and can't reach the hub's terminal (the same-user defense). |
| **shell `parse_command_chain` validation** | **DROP** | Floor patterns match the full command string; we run the command via the shell as-is. |
| **filesystem read-tracking** (`mark_file_read`/`reset_read_tracking` — block edit before read) | **DROP** | An agent-loop ergonomic requiring per-session state; MCP servers are stateless. Edit semantics belong to the harness. |
| **silent LLM-alias params** (`file_content`/`text`, `original_text`/`new_text`) | **DROP** | Robustness hack for the orchestrator's own LLM; MCP tools have a strict `inputSchema` and harnesses send canonical params. |
| **soft-delete to global trash** (`delete_file` → `get_global_deleted_files_dir`) | **CHANGE → hard delete** | Removes coupling to orchestrator storage paths; `delete_*` is floor-gated (prompt) so the safety lives at the hub. (Open Q1: keep a hub-managed trash instead?) |
| **`is_path_safe` / `RESTRICTED_PATHS`** (block `/etc/shadow`, `~/.ssh`, `/sys`, `/proc`, …) | **KEEP** (slim, re-implemented) | Cheap defense-in-depth against reading/clobbering OS-sensitive paths; not redundant with the floor (which is command-pattern, not path-based). |

## Default authz posture (seeded `default.yaml`)

Default-deny is implicit. Seeded rules: **reads allow, writes/exec prompt.**
- `allow`: `mcp://*/list_*`, `mcp://*/read_*`, `mcp://*/get_*`, plus `file_info`, `search_files`,
  `glob_files`, `find_files`, `fetch_webpage`, `search_internet`, `check_syntax`, `find_function`,
  `read_document`.
- `prompt`: `mcp://filesystem/create_file`, `edit_file`, `delete_file`, `mcp://shell/execute_command`.
  (Backgrounded hub → these fail-safe to deny, `no_approval_channel`.)
- Everything else: default-deny.

All five servers enabled by default (cheap stdio subprocesses). Users trim in `default.yaml`.

## Configuration toggles (per-server, via workspace `args`/`env`)

| Server | Flag | Default | Effect |
|---|---|---|---|
| filesystem | `--delete-mode soft\|hard` | `soft` | soft → trash dir; hard → unlink |
| filesystem | `--trash-dir PATH` | `~/.unified-ai/mcphub/trash` | where soft-deletes go |
| fetch | `--block-host HOST\|IP\|CIDR` | (none; `default.yaml` seeds metadata) | repeatable; the ONLY SSRF block list. Edit it to add/remove blocked hosts. A bare run blocks nothing. |
| fetch | `--search-backend auto\|duckduckgo\|brave\|none` | `auto` | `auto` = Brave if `BRAVE_API_KEY` set, else DuckDuckGo |
| fetch | (env `BRAVE_API_KEY`) | — | key for backend=brave; secrets-store injection is a follow-up |

Plus the model-level `enabled: true/false` on each server entry.

## Decisions (resolved)

1. **delete_file:** soft-delete by default to `~/.unified-ai/mcphub/trash/`; `--delete-mode hard` switches to unlink. ✅
2. **fetch SSRF:** guard **default-OFF** (revised). localhost/private/LAN fetches work with no flag and no prompt, matching the ecosystem norm. The only refusal is a **single configurable `blocked_hosts` list** (`--block-host`, repeatable), seeded by `default.yaml` with the cloud-metadata addresses — fully visible and editable (add to block more, remove to stop blocking). Per-call `allow_blocked=true` overrides the list for one call and is seeded to **prompt** with a warning (ADR-0018), keeping the override explicit + audited. The broad deny-all-private posture and a paired allowlist are **deferred to the cloud/shared-host hardening milestone** — they don't belong in the M0 local-dev default, and an allowlist only earns its place once deny-all-private exists. *Implementation note:* the prompt gate uses `args_filter` (`allow_blocked: { equals: ["true"] }`). This required generalizing `args_filter` into a per-argument operator map — the original form only inspected `command`/`path`/`repo`, so the gate would have failed open. See [ADR-0006 §Argument matching](../../docs/adrs/0006-mcp-hub-authz.md). ✅
3. **search_internet:** pluggable `--search-backend`, default `auto` (Brave if `BRAVE_API_KEY` present, else DuckDuckGo). Explicit `duckduckgo`/`brave`/`none` override. SearXNG moved to the container tier. ✅
4. **Enable all five by default.** ✅
5. **One `unified-mcp-servers` package**, modules per server; per-server enable/disable via `enabled`. ✅
6. **Rename `python-tools` → `python`** (`mcp://python/*`). ✅

## Out of scope (this tier)

Medium tier (`memory`, `browser`, `schedules`, `documents` PDF deps, …) and heavy tier
(`image_generation`, `vision`, `email`, `whatsapp`) — separate discussion. Containerized servers
(`image:`) are M0.5 (SEC-MCP-5).

- **SearXNG search backend** — dropped from this tier (only useful if the user self-hosts an
  instance; Brave + DuckDuckGo cover the M0 cases). Folded into the container/MCP-WRAP plan
  ([mcp-a2a-integration.md](../../docs/plans/mcp-a2a-integration.md)) where a `web-search`
  container is already planned — that's the natural home for a bundled SearXNG instance.
- **Broad SSRF guard (deny-all-private) + host allowlist** — deferred to the cloud/shared-host
  hardening milestone (see Decision 2). The M0 fetch default is guard-off + a single `blocked_hosts`
  denylist seeded with cloud-metadata addresses.
