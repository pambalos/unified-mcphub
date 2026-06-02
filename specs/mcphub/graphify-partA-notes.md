# graphify Part A — smoke-test notes (executed 2026-06-02)

Ran against `graphifyy[mcp]==0.8.28` on macOS (darwin 25.5.0), Python 3.12, with
the **`claude-cli` backend** (Claude Code CLI v2.1.150, subscription auth — **no
`ANTHROPIC_API_KEY`**). Test corpus: `graphify-smoketest/` (gitignored) =
`code/orders.py` + `design.pdf` + `design.png`.

## Fixtures (keyless, macOS built-ins)

- Code: `code/orders.py` — small module with class/methods/imports/calls.
- PDF: `printf '<prose>' | cupsfilter -i text/plain - > design.pdf` (15 KB, real text).
- Image: `sips -s format png design.pdf --out design.png` (612×792 PNG).

## Test 1 — keyless code-only (Pass 1, no LLM)

```sh
graphify extract ./code --backend claude-cli      # claude-cli NAMED but never invoked
```
- First attempt with **no `--backend`** → **errored**: `error: no LLM API key
  found … or pass --backend` (`__main__.py:3563` resolves a backend up front,
  before any work). → Must name a no-key backend even for code-only.
- With `--backend claude-cli`: **AST-only, no `claude` subprocess, $0.**
- Result graph: **8 nodes, 14 edges**, file_types `{code:7, rationale:1}`,
  relations `calls/contains/imports_from/method/references/rationale_for`,
  confidence **all `EXTRACTED`**. No semantic/INFERRED edges (Pass 3 skipped).
- Output landed at `<target>/graphify-out/graph.json` (relative to the *target*
  dir; `GRAPHIFY_OUT` env name-override did **not** take effect in this invocation
  — flagged for follow-up if we rely on it).

## Test 2 — mixed corpus (Pass 3 via claude-cli)

```sh
graphify extract . --backend claude-cli --max-concurrency 1
```
- Detected `3 code, 0 docs, 1 papers, 1 images` (PDF → "paper", PNG → "image").
- `semantic extraction on 2 files via claude-cli … chunk 1/1 done`.
- Result graph: **19 nodes, 22 edges, 4 communities**; file_types now include
  **`document:1`, `image:1`**; confidences **`EXTRACTED` + `INFERRED`**; new
  relation **`semantically_similar_to`** — all Pass-3-only signals, absent from
  Test 1. ✅ confirms the LLM path was exercised.
- Tokens: **43,445 in / 267 out, est. cost $0.00** (claude-cli = subscription).

## Test 3 — serve + query over MCP (stdio)

```sh
python -m graphify.serve <abs>/graphify-out/graph.json
```
- **10 tools** (spec said 7): `query_graph, get_node, get_neighbors,
  get_community, god_nodes, graph_stats, shortest_path, list_prs, get_pr_impact,
  triage_prs`.
- `query_graph(question="Order")` → BFS depth=3, returned Order + neighbors. ✅
- `graph_stats()` → `Nodes: 19, Edges: 22, Communities: 4, EXTRACTED 95% /
  INFERRED 5%`. ✅
- Arg-name notes: `query_graph` wants `question` (not `query`); `get_node` wants
  `label` (not `node_id`).
- `serve` takes the graph path as `argv[1]` (default `graphify-out/graph.json`,
  cwd-relative) → hub passes an **absolute** path, no cwd dependency.

## Timing — full pipeline on `unified-orchestrator` (632 code + 54 md + 1 img)

Measured to settle the sync-vs-async decision for `build_graph` (all via `claude-cli`):

- **Pass 1 (code only):** 632 files, 16 workers → **59 s wall, $0**, 14,071 nodes /
  29,670 edges / 423 communities. (Ran on a `/tmp` copy of code-only files.)
- **Pass 3 (docs):** graphify **chunks by ~60k-token budget**, not per file. A 5-md
  sample (1,510 lines) = **1 chunk = 77 s**, 32.8k in / 8.8k out, $0.
- **Pass 3 projected:** all 54 md ≈ 415 KB ≈ 104k tokens ≈ **2–3 chunks** ≈
  **~150–230 s serial** (`--max-concurrency 1`), ~$0 on subscription.
- **Full code+docs build ≈ 3–5 min serial; code-only ≈ 1 min.** SHA256 cache makes
  re-builds incremental automatically.

→ **Decision: v1 `build_graph` is synchronous**, client timeout ~600 s,
`--max-concurrency 1` for claude-cli. Async job model deferred to v2 for very large
/ doc-heavy repos (>10 min). (Orchestrator repo was never written to — all builds
ran in `/tmp`.)

## GRAPHIFY_OUT / output-location — resolved (source + behavior, v0.8.28)

- `graphify extract` writes the graph to **`<out_root>/graphify-out/graph.json`**,
  where `out_root` = the **`--out <DIR>`** flag if given, else the **target dir**
  (`__main__.py:3628-3629`). Subdir name `graphify-out` is hardcoded.
- **`GRAPHIFY_OUT` env is NOT honored by extract's main output.** It only feeds
  `_default_graph_path()` and side artifacts (`.graphify_root`, query/export
  defaults). In testing it created a stray `IGNORED_NAME/` dir but did **not**
  move the graph. Inconsistent — **avoid it.**
- Earlier confusion was a bad flag name (`--out-dir` doesn't exist; it's `--out`).
- **Wrapper decision:** don't use `GRAPHIFY_OUT` or `--out`. `build_graph(path)` →
  `graphify extract <path>` → graph deterministically at
  `<path>/graphify-out/graph.json`; queries load exactly that path.
- Cache lives at `<path>/graphify-out/cache/` (SHA256) → re-builds are incremental.

## Test 4 — drive `serve` through the hub via hand-edited workspace YAML ✅

Isolated temp `$UNIFIED_HOME`; hand-added a `graphify` server + authz rules.

- **Upstream that works:** `command: uvx`, `args: ["--with","mcp","--from",
  "graphifyy==0.8.28","python","-m","graphify.serve","<ABS graph.json>"]`.
  Hub log: `server 'graphify' connected (10 tools)`; `hub started … servers=[…,
  'graphify']`.
- **Authz:** seed wildcards `mcp://*/get_*` + `mcp://*/list_*` already cover
  `get_node/get_neighbors/get_community/get_pr_impact/list_prs`. The other 5
  (`query_graph, god_nodes, graph_stats, shortest_path, triage_prs`) needed
  explicit server-scoped `allow` rules — this is exactly the "unrecognized reads"
  case `add-server`'s probe will flag.
- **Tool names** are namespaced to callers as `graphify__<tool>`; authz URIs are
  `mcp://graphify/<tool>`.
- **Round-trip over the unix socket** (`curl --unix-socket … /mcp`,
  `X-Caller-Id` header, no token on uds):
  - `graphify__query_graph(question="Order")` → BFS traversal, `isError:false`.
  - `graphify__get_node(label="Order")` → node detail, `isError:false`.
- **Audit** captured both with correct decisions: `query_graph` →
  `allow` via `mcp://graphify/query_graph`; `get_node` → `allow` via `mcp://*/get_*`.

### ⚠️ Bug found: seed config breaks `$UNIFIED_HOME` isolation

The seeded `config.yaml` hardcodes literal `~/.unified-ai/mcphub/mcphub.sock`
(unix_socket) and `127.0.0.1:7712` (tcp) instead of respecting `$UNIFIED_HOME`. So
a temp-home hub's **socket points back at the REAL home**, and the transport
**unlinks any existing socket at that path on startup** (`transports.py:74-75`) —
clobbering a running real hub's socket. TCP `7712` likewise collides with the real
hub. (Cost us a real-hub disruption during this test.)

**Impact beyond us:** `add-server`'s Phase 0 relies on `UNIFIED_HOME=$(mktemp -d)
… init` to "never touch the real `~/.unified-ai/`" — this bug defeats that.

**Fixes to propose (hub core; coordinate with add-server agent — touches
config/seed):**
- Seed `config.yaml` should use `$UNIFIED_HOME`-relative paths (or omit
  `listen.*` and let `ListenConfig` defaults via `mcphub_home()` apply).
- Add `start --port N` / `--no-tcp` overrides (precedence CLI > config > default).
- Catch `Errno 48` on bind → friendly message instead of a 40-line traceback.

**Test-harness workaround (used here):** after `init`, rewrite the temp
`config.yaml` `listen.unix_socket` to the temp path and set `tcp: null`.

## Conclusions

- ✅ Code graph + all query tools are **backend-free at runtime** (a backend must
  be *named* for the `extract` CLI, but isn't *called* for code-only).
- ✅ `claude-cli` backend works with **no API key** and correctly drives the
  doc/image Pass-3 path. Recommended `--max-concurrency 1` for claude-cli.
- ⬜ Remaining: drive serve through the hub (hand-edit workspace YAML now, or via
  `add-server` once it lands); resolve the `GRAPHIFY_OUT` override behavior.
