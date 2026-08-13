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
# build + install the wrapper CLI from this repo (heavy: pulls graphify)
uv tool install ./packages/unified-mcp-graphify
# register the pre-installed binary with the hub (no fetch-at-spawn)
uv run unified-mcphub add-server graphify --command unified-mcp-graphify
```

See its [README](packages/unified-mcp-graphify) for the workspace entry, backend
options, and authz rules.

## Popular MCP servers

Third-party servers you can add to the hub with `add-server`. These are **not**
shipped in this repo — `add-server` pins them, probes the live tool surface, and
proposes default-deny authz rules (see [Adding MCP servers](packages/unified-mcphub/README.md#adding-mcp-servers)).

### Playwright — drive a real browser

[`@playwright/mcp`](https://github.com/microsoft/playwright-mcp) (Microsoft,
Apache-2.0) lets an agent **navigate and browse the live web through a real
browser** — `browser_navigate` / `browser_snapshot` / `browser_click` /
`browser_type` and ~20 more tools. It's a Node package, so **Node ≥18 must be on
PATH**, and the browser binaries are a separate, heavy (~100 MB headless Chromium)
opt-in download.

```sh
# 1. one-time: download the browser binary (heavy; Chromium only keeps it small)
npx playwright install chromium

# 2. register the pinned server with the hub, hardened for agent use:
#    --headless (no window) · --isolated (ephemeral profile, no persisted creds)
#    --blocked-origins (the only per-URL control — the hub gates tools, not URLs)
#    seeds loopback + IPv6-loopback + cloud-metadata across all ports (:*) so the
#    browser can't be turned into an SSRF pivot, while the open internet stays reachable.
uv run unified-mcphub add-server playwright \
  --npx '@playwright/mcp@0.0.75' \
  --arg --headless --arg --isolated \
  --arg --blocked-origins \
  --arg 'http://localhost:*;http://127.0.0.1:*;http://[::1]:*;http://169.254.169.254:*'
```

The probe classifies the `browser_*` tools as `prompt` (their names don't match the
read/write verb heuristic), so **curate the rules** — e.g. allow the read/navigate
loop (`browser_snapshot`, `browser_navigate`, `browser_click`, `browser_type`, …)
and keep **`browser_evaluate` / `browser_run_code_unsafe` denied** (they run
arbitrary JS in the page). Use `--configure-perms` for the per-tool wizard.

**Hardening notes** (all verified locally):
- **Strict containment:** swap the blocklist for an allowlist —
  `--arg --allowed-origins --arg 'https://docs.example.com;https://api.example.com'`
  makes *only* those origins reachable (everything else, including all loopback
  ports and other sites, is blocked). This is the high-security option.
- **No fetch-at-spawn (gold path):** pre-install the bin and point at it instead of
  npx — `npm i -g @playwright/mcp@0.0.75` then `add-server playwright --command playwright-mcp --arg …`.
- Origins are matched **scheme + host + port** and support globs, so a port
  wildcard (`http://127.0.0.1:*`) is required to cover all ports of a host.

## Quickstart

```sh
uv sync
uv run unified-mcphub start          # seeds ~/.unified-ai/mcphub on first run, runs in foreground
```

Point a harness at it, or query the socket directly (`~/.unified-ai/mcphub/mcphub.sock`).

### Install globally

To run `unified-mcphub` from any directory (no `uv run`, no `cd` into the repo),
install the CLI as a uv tool — `--editable` keeps it on live source, so code edits
take effect on the next run with no reinstall:

```sh
uv tool install --editable ./packages/unified-mcphub   # binary lands on PATH (~/.local/bin)
unified-mcphub start                                   # now works from anywhere
```

Reinstall (same command + `--reinstall`) only when `dependencies` change; plain
source edits need no reinstall. The optional `graphify` server installs separately
(see [Optional servers](#optional-servers)).

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
