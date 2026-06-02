# unified-mcphub

A local **MCP hub** — one audited, policy-gated MCP server that every AI harness
on your machine connects to, instead of each wiring up its own tool servers.
Default-deny authz, an approval TUI, an append-only audit log, and a bundled
tier of light/safe tool servers out of the box.

## Layout

A uv workspace of three packages:

| Package | What it is |
|---|---|
| [`unified-mcphub`](packages/unified-mcphub) | the hub CLI + server (authz, audit, approval, supervisor, transports) |
| [`unified-mcp-client`](packages/unified-mcp-client) | async MCP client (stdio + streamable-HTTP) the hub uses to talk to upstream servers |
| [`unified-mcp-servers`](packages/unified-mcp-servers) | first-party light/safe stdio servers: `filesystem`, `shell`, `fetch`, `python`, `documents` |

This repo is **standalone** — it does not depend on the orchestrator. Architecture
decisions (ADRs) and roadmap live in the separate `unified-ai-docs` repo; the
implementation specs for this product live under [`specs/mcphub/`](specs/mcphub).

### Optional servers

Heavier, opt-in servers live under `packages/` but are **excluded from the uv
workspace** (large deps) — built and run standalone via `uvx`, then added like any
upstream with `add-server`:

| Package | What it adds |
|---|---|
| [`unified-mcp-graphify`](packages/unified-mcp-graphify) | build + query [graphify](https://github.com/safishamsi/graphify) code-knowledge graphs for any repo over MCP — `build_graph` / `graph_status` / 7 graph-query + 3 GitHub-PR tools, all per-call `path` |

```sh
# once published to your index:
uv run unified-mcphub add-server graphify --uvx 'unified-mcp-graphify==0.1.0'
```

Until then, install it from this repo (`packages/unified-mcp-graphify`). See its
[README](packages/unified-mcp-graphify) for the workspace entry, backend options,
and authz rules.

## Quickstart

```sh
uv sync
uv run unified-mcphub start          # seeds ~/.unified-ai/mcphub on first run, runs in foreground
```

Point a harness at it, or query the socket directly (`~/.unified-ai/mcphub/mcphub.sock`).

Wire a harness with `uv run unified-mcphub install claude-code`. Secret-shaped output
is redacted by default; for the extra-safe path (a Claude Code redaction hook + the
workspace `redact:` result policy) see
[Secret redaction](packages/unified-mcphub/README.md#secret-redaction-defense-in-depth).

Add an upstream MCP server with `uv run unified-mcphub add-server NAME --npx 'PKG@ver'` — it
probes the server and proposes default-deny authz rules. See
[Adding MCP servers](packages/unified-mcphub/README.md#adding-mcp-servers).

## Develop

```sh
uv run pytest packages/unified-mcphub/tests packages/unified-mcp-servers/tests
uv run ruff check packages
# optional servers are excluded from the workspace — test them on their own:
( cd packages/unified-mcp-graphify && uv run --extra dev pytest )
```

## License

Proprietary — All Rights Reserved. See [LICENSE](LICENSE).
