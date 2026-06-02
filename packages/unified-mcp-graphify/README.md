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
| `build_graph(path, backend, deep)` | **subprocess** `graphify extract` (stable build contract; no drift across graphify releases) | `prompt` |
| `graph_status(path)` | own code: git-HEAD staleness | `allow` |
| `query_graph` · `get_node` · `get_neighbors` · `get_community` · `god_nodes` · `graph_stats` · `shortest_path` | **library import** from `graphify.serve` helpers (in-process, fast) | `allow` |
| `list_prs` · `get_pr_impact` · `triage_prs` | **library import** from `graphify.prs`; run `gh`/`git` with cwd = `path` | `allow` |

- Graph lives at the **native** `<path>/graphify-out/graph.json`; graphs are
  mtime-cached so repeat queries don't re-parse.
- `build_graph` defaults to the **`claude-cli`** backend — keyless (uses the local
  Claude Code subscription). Code-only repos never invoke it; doc/PDF/image
  corpora use it for semantic extraction. Synchronous (minutes on large repos);
  graphify's SHA256 cache makes re-builds incremental.
- **graphify is pinned in this package's `pyproject.toml`** (`graphifyy[mcp]==0.8.28`)
  so a hub/workspace config edit can't silently change it.
- The PR tools require `gh` to be installed and authenticated; they operate on the
  git repo at `path` (and accept an optional `repo` = `owner/repo`).

## Heaviness

graphify pulls ~29 tree-sitter grammars + an LLM backend, so this package is
**excluded from the uv workspace** and is never a dependency of the hub core or
the tiny `unified-mcp-servers` tier. It is built and run standalone via `uvx`.

## Add to a workspace

```yaml
servers:
  graphify:
    enabled: true
    upstream:
      command: uvx
      args: ["unified-mcp-graphify==0.1.0"]
# authz (probe proposes; operator confirms):
#   query_graph / get_* / god_nodes / graph_stats / shortest_path → allow
#   list_prs / get_pr_impact / triage_prs                         → allow
#   build_graph                                                    → prompt
```

## Develop / test

This package is outside the workspace, so run its tests standalone:

```sh
cd packages/unified-mcp-graphify
uv run --extra dev pytest -q
```
