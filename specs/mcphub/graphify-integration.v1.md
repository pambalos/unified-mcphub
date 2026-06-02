# Plan — graphify integration: smoke-test + "init-anywhere" MCP wrapper

Status: **exploratory** · Target milestone: M0.75+ (after `add-server`) · Owner: TBD

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
`python -m graphify.serve`: `query_graph`, `get_node`, `get_neighbors`,
`shortest_path`, `list_prs`, `get_pr_impact`, `triage_prs`. The graph is built by
a *separate* step (`/graphify .` or `graphify extract …`), **not** by agent tool
calls — that build step is the gap Part B closes for MCP-first usage.

> Heaviness note: graphify pulls tree-sitter, optional faster-whisper, and an LLM
> backend (Claude/Gemini/OpenAI/Ollama/Bedrock/Kimi). It must **NOT** live in the
> `unified-mcp-servers` "deliberately tiny, stdlib-only" tier. It stays an
> external/optional server, added via `add-server`.

---

## Part A — set up & smoke-test graphify (no new code)

1. **Verify the package name** — repo shows `uv tool install graphifyy` (double-y)
   vs. module `graphify`. Confirm the real PyPI name before scripting anything.
2. **Install isolated**: `uv tool install <pkg>` (or `uvx <pkg>` for ephemeral).
3. **Pick an LLM backend** — extraction needs one. For a privacy-preserving,
   no-API-key smoke test, try **Ollama** locally; otherwise wire a key via the
   hub `secrets` store and pass it through `env:`.
4. **Build a graph** on a small sample repo: `graphify extract ./<sample>
   --backend <provider>` → confirm `graph.json` + report are produced.
5. **Run the server** and confirm tools: `python -m graphify.serve` →
   `list_tools` shows the 7 query tools.
6. **Drive it through the hub** (temp `$UNIFIED_HOME`): once `add-server` exists,
   `unified-mcphub add-server graphify --uvx <pkg> --arg serve` (or
   `--command python --arg -m --arg graphify.serve`). Then `list-tools` via the
   hub and call `query_graph` / `get_node` through the socket.
   - **Authz reality check** — the probe will flag `query_graph`, `shortest_path`,
     `triage_prs` as *unrecognized* (reads that don't match `read_/list_/get_`),
     proving the probe-then-confirm value. Confirm them as `allow`.
   - **Open question — how does `serve` locate `graph.json`?** cwd vs. a flag/env.
     This decides whether per-repo use needs the hub to launch the server with
     `cwd = target repo` (the hub's `StdioConnection` does not currently set cwd —
     see Part B) or just a `--graph PATH` arg.

Deliverable: a working "extract → serve → query through the hub" loop documented
in notes, plus the answer to the graph-location question.

---

## Part B — the "init-anywhere" wrapper server

Vanilla graphify makes you run a CLI extract step before the MCP query tools
return anything, and `serve` is tied to one graph location. The wrapper closes
both gaps with a thin MCP server that **adds an init/build tool** and makes
graphify **repo-relative**.

### Shape

A small, separate optional package (e.g. `unified-mcp-graphify`, its own
workspace member or standalone repo — kept out of the tiny default tier). Depends
on `graphify` + `mcp` + the shared `unified-mcp-client` is not needed (this is a
server, not a client). Run via `uvx` / stdio; added to a workspace with
`add-server`.

Tools exposed:

- `build_graph(path, backend=?, incremental=?)` — **the new capability**: run
  graphify extraction for `path` (defaults to the server's working repo),
  managing a per-repo `graph.json` location (e.g. `<path>/.graphify/graph.json`).
  Returns a summary (node/edge counts, report path). This is a **write/compute**
  tool → `prompt` under hub authz.
- `graph_status(path)` — whether a graph exists for `path`, when built, staleness
  vs. git HEAD. Read → `allow`.
- **Passthrough query tools** — `query_graph`, `get_node`, `get_neighbors`,
  `shortest_path`, `list_prs`, `get_pr_impact`, `triage_prs`, each operating on
  the resolved per-repo graph. Reads → `allow` (operator confirms via probe).

### Two implementation strategies (pick after Part A)

1. **Library-import wrapper (preferred if graphify exposes a clean API):** import
   graphify's extraction + query functions directly, point them at a
   per-repo/per-call graph path, and re-export them as MCP tools. Cleanest;
   gives full control over graph location and the `build_graph` tool.
2. **Subprocess/proxy wrapper (fallback):** shell out to `graphify extract` for
   `build_graph`, and either (a) proxy to a child `graphify.serve` for queries
   (the wrapper is then a mini-hub for one server) or (b) re-run query CLIs.
   Simpler to start, heavier at runtime.

Strategy choice hinges on Part A's findings (does `graphify` expose importable
functions, and how does `serve` locate its graph).

### Repo-agnostic launch — the cwd question

To use it "in any repo," the server needs to know *which* repo. Options:
- **Per-call `path` argument** on every tool (most flexible; no cwd dependency).
- **Launch with `cwd = repo`** — but the hub's `StdioConnection` does not
  currently set `cwd`. If we go cwd-based, that's a **small upstream change**:
  add an optional `cwd` to `Upstream` / `StdioConnection`, threaded through
  `supervisor._make_connection`. Worth doing anyway (generally useful for stdio
  servers), but call it out as a dependency.

Recommendation: **per-call `path` argument** for the wrapper (no hub change
needed), with `cwd` support as an optional later enhancement.

### Config / authz sketch (added via `add-server`)

```yaml
graphify:
  enabled: true
  upstream:
    command: uvx
    args: ["unified-mcp-graphify"]
    env: { GRAPHIFY_BACKEND: "ollama" }   # or a secret-ref'd API key
# authz (probe proposes; operator confirms):
#   query_graph / get_* / list_* / shortest_path / *_impact  → allow
#   build_graph                                              → prompt
```

---

## Risks / open points

- **Package name** (`graphify` vs `graphifyy`) — verify first.
- **LLM backend dependency** — extraction isn't purely local; needs Ollama or an
  API key. The wrapper must surface a clear error if no backend is configured,
  and we should prefer a local backend for the default test.
- **License** — confirm graphify's license permits wrapping/redistribution before
  shipping `unified-mcp-graphify` as a package.
- **Heaviness isolation** — keep it a separate optional package; never a dep of
  `unified-mcp-servers` or the hub core.
- **Graph staleness** — a built graph drifts from the code; `graph_status`
  staleness vs. git HEAD + an `incremental` rebuild option mitigate this.
- **Concurrency / size** — large repos → long extraction; `build_graph` may need
  progress reporting (graphify's `longRunningOperation`-style notifications) and a
  generous client timeout.
