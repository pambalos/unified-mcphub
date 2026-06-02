# Plan — graphify integration: smoke-test + "init-anywhere" MCP wrapper

Status: **exploratory** (recon complete 2026-06-02 — see Verified facts) · Target milestone: M0.75+ (after `add-server`) · Owner: TBD

Two separate goals, sequenced:

- **Part A** — stand up [safishamsi/graphify](https://github.com/safishamsi/graphify)
  in/alongside this repo and verify the hub can drive its query tools end to end
  (validates the `add-server` path against a realistic heavyweight server).
- **Part B** — design a **lightweight wrapper MCP server** that lets us
  *initialize* graphify on demand for **any repo** over MCP (not just query a
  pre-built graph), so an agent can say "build the graph for this project, then
  query it" without leaving the harness.

Context: graphify is a Python code-comprehension engine. It **auto-extracts** a
knowledge graph from a codebase/docs/media (tree-sitter across 33 languages +
LLM-driven semantic extraction), stores it as local `graph.json` (optional Neo4j
export + HTML viz), and exposes a **read-only** MCP query surface via
`python -m graphify.serve` (10 tools — see Verified facts): `query_graph`,
`get_node`, `get_neighbors`, `get_community`, `god_nodes`, `graph_stats`,
`shortest_path`, `list_prs`, `get_pr_impact`, `triage_prs`. The graph is built by
a *separate* step (`/graphify .` or `graphify extract …`), **not** by agent tool
calls — that build step is the gap Part B closes for MCP-first usage.

> Heaviness note: graphify pulls tree-sitter, optional faster-whisper, and an LLM
> backend (Claude/Gemini/OpenAI/Ollama/Bedrock/Kimi). It must **NOT** live in the
> `unified-mcp-servers` "deliberately tiny, stdlib-only" tier. It stays an
> external/optional server, added via `add-server`.

---

## Verified facts (PyPI + upstream source review — 2026-06-02)

Findings from inspecting [safishamsi/graphify](https://github.com/safishamsi/graphify)
@ v0.8.28 and the PyPI metadata. These resolve several open points below.

- **Package name = `graphifyy`** (double-y) on PyPI; the **import/module name is
  `graphify`** (so `python -m graphify.serve`). Bare `graphify` 404s on PyPI.
- **`mcp` is an optional extra, not a core dep** (`mcp; extra == "mcp"`). The
  query/serve surface only exists if installed as **`graphifyy[mcp]`**. Part B's
  package must depend on `graphifyy[mcp]`.
- **License = MIT** (© 2026 Safi Shamsi). Wrapping + redistribution as
  `unified-mcp-graphify` is permitted. (Resolves the license open-point.)
- **No LLM backend is needed for code repos — or for querying, ever.** graphify
  runs three passes (`docs/how-it-works.md`):
  - *Pass 1 — code structure*: tree-sitter AST (classes/functions/imports/call
    graph). **Fully local, no API calls.**
  - *Pass 2 — video/audio*: faster-whisper, local. (Irrelevant to code.)
  - *Pass 3 — docs/papers/images*: LLM semantic extraction. **Only runs when such
    files exist** — gated by `if semantic_files:` in `__main__.py:3710`
    (`semantic_files = doc_files + paper_files + image_files`). A code-only corpus
    skips Pass 3 entirely; the backend is never touched.
  - The **query server (`serve.py`) imports no LLM module at all** — the query
    tools operate purely on the local `graph.json`. Backend-free regardless of
    corpus.
- **CLI gotcha (verified by running it): `graphify extract` still requires a
  backend to be _named_ up front, even for code-only.** At `__main__.py:3563` it
  auto-detects a backend from env keys and, finding none, **errors before doing any
  work** (`error: no LLM API key found … or pass --backend`). The fix for a keyless
  code run is to **name a no-key backend explicitly: `--backend claude-cli`** (or
  `bedrock`). Since Pass 3 is skipped for code-only, the backend is never actually
  invoked — extraction is pure AST, $0, no `claude` subprocess. (The library API
  `graphify.extract.extract()` has no such gate; Part B's library-import strategy
  can do code extraction with no backend named at all.)
- **Tool surface is 10 tools, not 7** (verified via stdio probe): `query_graph`,
  `get_node`, `get_neighbors`, `get_community`, `god_nodes`, `graph_stats`,
  `shortest_path`, `list_prs`, `get_pr_impact`, `triage_prs`. Arg-name notes:
  `query_graph` takes `question` (not `query`); `get_node` takes `label` (not
  `node_id`). The PR tools (`list_prs`/`get_pr_impact`/`triage_prs`) need a git+gh
  context; the graph-query tools do not.
- **Two backends need no API key** when Pass 3 *is* wanted (e.g. graphing docs):
  - **`claude-cli`** — routes through the locally-installed Claude Code CLI
    (`claude -p`) using the existing subscription auth; the API-key check is
    skipped for it (`llm.py:698`, `llm.py:1108`). This is our test backend.
  - **`bedrock`** — uses the AWS IAM credential chain.
  - Community **naming** degrades gracefully to `Community N` with no backend
    (`llm.py:1368`); `--no-label` skips it outright. Naming is cosmetic.
- **`serve` graph location is resolved — no cwd dependency.**
  `python -m graphify.serve <PATH>` takes the graph file as `sys.argv[1]`,
  defaulting to `graphify-out/graph.json` (cwd-relative) (`serve.py:991-993`).
  The hub can pass an **absolute** graph path as an arg, so the Part B "cwd
  question" is moot for `serve` (it only matters for `build_graph`). graphify's
  own recommended MCP config does exactly this (`__main__.py:847`):
  `... -m graphify.serve ${workspace.path}/graphify-out/graph.json`.
- **Even the hub's `StdioConnection` already supports `cwd`**
  (`unified-mcp-client/.../client.py` — `cwd` param plumbed into
  `StdioServerParameters`). The only gap, if we ever go cwd-based, is that
  `Upstream` has no `cwd` field and `supervisor._make_connection` (supervisor.py:63)
  doesn't thread it — a one-field config change, not a client change. (The earlier
  claim that `StdioConnection` "does not set cwd" was inaccurate.)
- **Output dir override**: `GRAPHIFY_OUT` env var redirects `graphify-out/`
  (relative name or absolute path) — useful for per-repo / worktree isolation.

---

## Part A — set up & smoke-test graphify (no new code)

Package name, license, and the graph-location question are **resolved** above. The
remaining work is to actually exercise the two paths that matter: the **keyless
code path** (Pass 1) and the **LLM semantic path** (Pass 3) via the no-API-key
`claude-cli` backend.

1. **Install isolated** as `graphifyy[mcp]` (the `mcp` extra is required for the
   serve surface): `uv tool install "graphifyy[mcp]"`, or ephemerally
   `uvx --from "graphifyy[mcp]" graphify …` / `uvx --with mcp --from graphifyy
   python -m graphify.serve …`. Confirm the `graphify` console command and the
   `graphify.serve` module are both available.

2. **Keyless code smoke test (Pass 1 — no backend).** Build a graph over a small
   *code-only* sample (e.g. one of this repo's `packages/`):
   `graphify extract ./<code-sample>` → confirm `graphify-out/graph.json` +
   `GRAPH_REPORT.md` are produced **with no backend configured** (proves Pass 3 is
   skipped and no key/Ollama is required). Then serve + query it (step 4).

3. **`claude-cli` semantic test (Pass 3 — no API key).** This is the path we want
   to deliberately exercise. Build a tiny **mixed** corpus that forces Pass 3:
   - a code file (Pass 1),
   - a **PDF** with real prose — generate keyless on macOS:
     `printf '<design-doc text>' | cupsfilter -i text/plain - > corpus/design.pdf`,
   - an **image** with text/diagram — render the PDF to PNG:
     `sips -s format png corpus/design.pdf --out corpus/design.png`.

   Run: `graphify extract ./corpus --backend claude-cli` (uses the local Claude
   Code subscription; **no `ANTHROPIC_API_KEY`**). Confirm the report shows
   `document` / `image` nodes and `semantically_similar_to` / `references` edges
   that only Pass 3 produces, and that `claude -p` subprocesses were invoked.
   - Notes to capture: `--max-concurrency 1` is recommended for `claude-cli`
     (parallel subprocesses conflict unless `GRAPHIFY_CLAUDE_CLI_PARALLEL=1`,
     `llm.py:1034`); wall-clock and token cost on the tiny corpus; any prompts the
     CLI raises on first invocation.

4. **Run the server** and confirm tools: `python -m graphify.serve
   <abs>/graphify-out/graph.json` → `list_tools` shows the 10 query tools. Call
   `query_graph` (`question=…`) / `graph_stats` directly to confirm they read the
   graph.

5. **Drive it through the hub** (temp `$UNIFIED_HOME`). Two routes:
   - **Now, without `add-server` — DONE & verified** (see Part-A notes Test 4).
     Hand-edit the workspace YAML. The upstream **cannot** be bare
     `python -m graphify.serve` — the hub rewrites bare `python` to *its own*
     venv, which lacks graphify (supervisor.py:62). Use uvx:
     ```yaml
     graphify:
       enabled: true
       upstream:
         command: uvx
         args: ["--with", "mcp", "--from", "graphifyy==0.8.28",
                "python", "-m", "graphify.serve", "<ABS>/graphify-out/graph.json"]
     ```
     Result: `server 'graphify' connected (10 tools)`; `query_graph`/`get_node`
     called through the unix socket return data; audit logs the allow decisions.
   - **Later, via `add-server`** (when it lands) — re-run the same, generated by
     `add-server` (probe → propose rules). Then re-confirm the round-trip.
   - **Authz reality check (confirmed):** seed wildcards `mcp://*/get_*` +
     `mcp://*/list_*` cover `get_*`/`list_prs`; the other 5 (`query_graph`,
     `god_nodes`, `graph_stats`, `shortest_path`, `triage_prs`) are *unrecognized*
     reads needing explicit `allow` rules — exactly what `add-server`'s probe flags.
   - **⚠️ Isolation caveat:** the seeded `config.yaml` hardcodes
     `~/.unified-ai/...` socket + `127.0.0.1:7712`, so a temp `$UNIFIED_HOME` hub
     still points at the **real** socket/port and the transport unlinks it on
     start — it *can clobber a running real hub*. Workaround for testing: after
     `init`, rewrite the temp `config.yaml` `listen.unix_socket` to the temp path
     and set `tcp: null`. **Proper fix is a hub-core change** (seed should respect
     `$UNIFIED_HOME`; add `start --port`/`--no-tcp`; friendly bind-error) —
     coordinate with the `add-server` agent since it touches config/seed/cli.

Deliverable: a notes file recording (a) the keyless code loop, (b) the working
`claude-cli` Pass-3 run with the PDF+image fixture, and (c) the extract → serve →
query-through-the-hub loop.

---

## Part B — the "init-anywhere" wrapper server

Vanilla graphify makes you run a CLI extract step before the MCP query tools
return anything, and `serve` is tied to one graph location. The wrapper closes
both gaps with a thin MCP server that **adds an init/build tool** and makes
graphify **repo-relative**.

### Shape (decided)

A small, separate optional package `unified-mcp-graphify`, a **workspace member**
kept out of the tiny default tier. It **pins graphify in its own `pyproject.toml`**
(`graphifyy[mcp]==0.8.28`) — so the *wrapper* owns the graphify version and a
*config* edit can never silently bump it and break things. The workspace YAML
just points at our pinned wrapper; graphify's pin rides along transitively, and
add-server's `require_pinned_versions` is satisfied at our package level. Also
depends on `mcp`. (`unified-mcp-client` is not needed — this is a server.) Run via
`uvx` / stdio; added to a workspace with `add-server`.

**Every tool takes a per-call `path`** (no cwd dependency — see below) and resolves
the graph at graphify's **native** location `<path>/graphify-out/graph.json`
(`GRAPHIFY_OUT`-overridable), so the wrapper and a direct `graphify extract` agree.

Tools exposed (v1 = the full set):

- `build_graph(path, backend="claude-cli", deep=False)` — **the new capability**:
  run graphify extraction for `path`. **Synchronous** (see timing below); returns
  a summary (node/edge counts, report path). **Write/compute → `prompt`** under hub
  authz. graphify's SHA256 cache makes re-builds incremental automatically.
- `graph_status(path)` — whether a graph exists for `path`, when built, staleness
  vs. git HEAD (our own code; graphify doesn't expose this). Read → `allow`.
- **Query tools (10), per-call `path`** — `query_graph`, `get_node`,
  `get_neighbors`, `get_community`, `god_nodes`, `graph_stats`, `shortest_path`,
  `list_prs`, `get_pr_impact`, `triage_prs`. Reads → `allow`. The PR tools
  (`list_prs`/`get_pr_impact`/`triage_prs`) additionally need a git+gh context for
  `path`; the graph-query tools do not.

### Implementation strategy: hybrid (decided after Part A source review)

Part A settled the two questions the strategy hinged on:
- **Query functions ARE importable** — `graphify.serve` exposes `_load_graph`,
  `_query_graph_text`, `_find_node`, `_score_nodes`, `_bfs`, etc. (the functions
  its own MCP tools wrap).
- **There is NO public build orchestrator** — `extract`/`build_from_json`/`cluster`
  etc. are public, but the orchestration (detect → parallel AST → semantic gating
  → cache → cluster → analyze → report → export) lives only in `__main__.py`'s CLI
  dispatcher. A pure library build would mean re-implementing + re-syncing that on
  every graphify release (churn = 144 releases).

So the wrapper is a **hybrid**:

| Tool(s) | Implementation | Rationale |
|---|---|---|
| `build_graph` | **subprocess** `graphify extract <path> --backend …` | Heavy/long/isolatable; the CLI is graphify's stable build contract → zero re-sync burden, full pipeline + progress for free |
| `graph_status` | **our own code** | file mtime + `git rev-parse HEAD` staleness; not in graphify |
| 10 query tools | **library import** from `graphify.serve` | fast, in-process, per-call `path`, no child process per query; load `<path>/graphify-out/graph.json` on demand (mtime-cached) |

### Sync vs. async — measured, sync chosen for v1

Timed against `unified-orchestrator` (632 code + 54 md + 1 img) with `claude-cli`:

- **Pass 1 (code only): ~59 s**, $0, no LLM (14k nodes / 29.7k edges).
- **Pass 3 (docs):** graphify chunks docs by ~60k-token budget, so cost tracks doc
  *volume*, not file count. 54 md ≈ 104k tokens ≈ 2–3 chunks ≈ ~150–230 s serial
  (`--max-concurrency 1`), ~$0 on subscription.
- **Full code+docs build ≈ 3–5 min serial; code-only ≈ 1 min.**

→ **v1 is synchronous** with a **generous client timeout (~600 s)** and
`--max-concurrency 1` for claude-cli stability. The common code-graph path (~1 min)
feels responsive; the SHA256 cache makes re-builds cheap.

→ **Async job model is v2**, for the boundary case: very large or doc-heavy repos
(thousands of docs → many chunks → >10 min). Then `build_graph` returns a job id
and `graph_status` polls. Not needed for the target use case; named here as the
escape hatch.

### Repo-agnostic launch — resolved: per-call `path`

**Decided: per-call `path` argument on every tool.** No cwd dependency, no hub
change, and it's the only model that supports building/querying *arbitrary* repos
from one running server instance (the actual requirement). A static `serve` entry
can't do this — it's bound to one graph at launch — which is exactly why the
wrapper exists rather than just pointing the YAML at `serve`.

(For reference: the hub's `StdioConnection` *already* supports `cwd`; only
`Upstream`/`supervisor._make_connection` don't thread it. A cwd-based model would
still be inferior here since one server must serve many repos.)

### Config / authz sketch (added via `add-server`)

```yaml
graphify:
  enabled: true
  upstream:
    command: uvx
    # The wrapper is pinned; graphify's version is pinned INSIDE the wrapper's
    # pyproject (graphifyy[mcp]==0.8.28), not here — so this config can't bump it.
    args: ["unified-mcp-graphify==0.1.0"]
    # build_graph defaults backend=claude-cli (keyless, subscription). Override only
    # to graph docs with a different provider:
    # env: { GRAPHIFY_BACKEND: "claude-cli" }
# authz (probe proposes; operator confirms) — all per-call `path`:
#   query_graph / get_* / list_* / god_nodes / graph_stats / shortest_path / *_impact → allow
#   build_graph                                                                        → prompt
```

> **Why not just point the YAML at `graphify.serve`?** Because `serve` binds to one
> graph at launch. The whole reason for this wrapper is **build + query for
> *arbitrary* repos on demand** (per-call `path`) — and exposing `build_graph` as an
> MCP tool, which `serve` doesn't. For a single fixed pre-built graph, a plain
> `serve` YAML entry is still the lighter choice and needs no wrapper.

---

## Risks / open points

- ~~**Package name** (`graphify` vs `graphifyy`)~~ — **resolved**: install
  `graphifyy[mcp]`, import `graphify`. See Verified facts.
- ~~**License**~~ — **resolved**: MIT, wrapping/redistribution permitted.
- **LLM backend dependency** — **largely a non-issue, corrected.** Code extraction
  and *all* query tools are fully local (no backend). A backend is required **only**
  to extract non-code content (docs/PDFs/images, Pass 3), and even then `claude-cli`
  (subscription) and `bedrock` (IAM) need no API key. The wrapper should still
  surface a clear error if `build_graph` is asked to process non-code files with no
  backend configured — but the default code path must never require one.
- **Heaviness isolation** — keep it a separate optional package; never a dep of
  `unified-mcp-servers` or the hub core. (Confirmed heavy: 29 `tree-sitter-*`
  grammars are *core* deps even before extras.)
- **Version churn / pinning** — graphify ships frequently (v0.8.28, 144 releases).
  Pin `graphifyy[mcp]==<ver>` per the `add-server` `require_pinned_versions`
  policy; bare `uvx graphifyy` is a moving target.
- **Graph staleness** — a built graph drifts from the code; `graph_status`
  staleness vs. git HEAD + an `incremental` rebuild option mitigate this.
- **Concurrency / size** — large repos → long extraction; `build_graph` may need
  progress reporting (graphify's `longRunningOperation`-style notifications) and a
  generous client timeout. For `claude-cli` specifically, default to
  `--max-concurrency 1` unless `GRAPHIFY_CLAUDE_CLI_PARALLEL=1`.
- **Python 3.13 caveat** — the `leiden` community-detection extra (`graspologic`)
  is gated `python_version < "3.13"`. Fine on the planned 3.12 floor; would
  silently drop on 3.13.
