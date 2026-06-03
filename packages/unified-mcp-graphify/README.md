# unified-mcp-graphify

An **optional** MCP server that builds and queries [graphify](https://github.com/safishamsi/graphify)
knowledge graphs for **arbitrary repos on demand** — every tool takes a per-call
`path`, so one running server can build/query any project.

Why a wrapper (vs. pointing the hub straight at `graphify.serve`)? Vanilla
`graphify.serve` is read-only and bound to **one** graph at launch, and the build
step is a CLI command, not an MCP tool. This wrapper adds `build_graph` over MCP
and makes every tool repo-relative. For a single, fixed, pre-built graph a plain
`graphify.serve` workspace entry is still the lighter choice.

## Design (see `specs/mcphub/graphify-integration.v1.md`, Part B)

Hybrid implementation:

| Tool(s) | How | Authz |
|---|---|---|
| `build_graph(path, backend, deep)` | starts a background **subprocess** `graphify extract` (stable build contract; no drift across graphify releases) and returns immediately | `prompt` |
| `build_status(path)` | own code: poll an in-flight / finished build (falls back to on-disk `graph_status` when idle) | `allow` |
| `graph_status(path)` | own code: git-HEAD staleness | `allow` |
| `query_graph` · `get_node` · `get_neighbors` · `get_community` · `god_nodes` · `graph_stats` · `shortest_path` | **library import** from `graphify.serve` helpers (in-process, fast) | `allow` |
| `list_prs` · `get_pr_impact` · `triage_prs` | **library import** from `graphify.prs`; run `gh`/`git` with cwd = `path` | `allow` |

- Graph lives at the **native** `<path>/graphify-out/graph.json`; graphs are
  mtime-cached so repeat queries don't re-parse.
- `build_graph` is **asynchronous**: it spawns the extraction on a background
  thread and returns immediately with `state: "running"`, then you poll
  `build_status(path)` until `done`/`failed`. Builds can run many minutes on
  large/doc-heavy repos — longer than an MCP client's per-call timeout (the
  Claude Code harness default is 120s) — so a single blocking call would time
  out; the poll model avoids that. The job registry is in-process (a job lives
  only as long as the running server), but graphify's SHA256 cache makes a
  restart-and-rebuild incremental, and concurrent builds of the same `path` are
  deduped.
- `build_graph` defaults to the **`claude-cli`** backend — keyless (uses the local
  Claude Code subscription). Code-only repos never invoke it; doc/PDF/image
  corpora use it for semantic extraction.
- **graphify is pinned in this package's `pyproject.toml`** (`graphifyy[mcp]==0.8.28`)
  so a hub/workspace config edit can't silently change it.
- The PR tools require `gh` to be installed and authenticated; they operate on the
  git repo at `path` (and accept an optional `repo` = `owner/repo`).

## Heaviness

graphify pulls ~29 tree-sitter grammars + an LLM backend, so this package is
**excluded from the uv workspace** and is never a dependency of the hub core or
the tiny `unified-mcp-servers` tier. It is built and run standalone via `uvx`.

## Install & add to a workspace

Not yet published — install the CLI from this repo, then register the
pre-installed binary with the hub (no fetch-at-spawn):

```sh
uv tool install ./packages/unified-mcp-graphify
uv run unified-mcphub add-server graphify --command unified-mcp-graphify
```

`add-server` probes the server and proposes default-deny authz rules. The
resulting workspace entry looks like:

```yaml
servers:
  graphify:
    enabled: true
    upstream:
      command: unified-mcp-graphify   # the uv-tool-installed console script
# authz (probe proposes; operator confirms):
#   query_graph / get_* / god_nodes / graph_stats / shortest_path → allow
#   list_prs / get_pr_impact / triage_prs                         → allow
#   build_status / graph_status (read-only polls)                 → allow
#   build_graph                                                    → prompt
```

> `build_status` / `graph_status` are read-only but trip the classifier's
> "unrecognized verb → prompt" safe default. Confirm them to `allow` at
> add-server time — `build_status` is a poll, so leaving it on `prompt` nags on
> every status check.

(Once published, `--uvx 'unified-mcp-graphify==<ver>'` will be the one-liner.)

## Building & querying a graph

`build_graph` returns immediately; poll `build_status` until the build finishes,
then run any query tool.

```text
build_graph(path="/repo")              -> {ok: true, state: "running", ...}
build_status(path="/repo")             -> {state: "running", elapsed_s: 12.5, ...}
build_status(path="/repo")             -> {state: "done", nodes: 1432, edges: 2871,
                                           communities: 57, graph_json: ".../graph.json"}
graph_stats(path="/repo")              -> "Nodes: 1432\nEdges: 2871\n..."
```

`build_status` returns `state: "idle"` (plus the on-disk `graph_status`) if no
build has run this session — so you can tell whether a graph already exists from
a prior run before kicking off a new build.

## Develop / test

This package is outside the workspace, so run its tests standalone:

```sh
cd packages/unified-mcp-graphify
uv run --extra dev pytest -q
```

For a full end-to-end check — stand up the real stdio server, run an actual
(code-only, no-LLM) build over the MCP protocol, and poll `build_status` to
completion:

```sh
uv run python e2e_check.py
```
