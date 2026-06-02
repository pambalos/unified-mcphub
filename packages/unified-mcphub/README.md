# unified-mcphub

Local MCP hub — one audited, policy-gated MCP server for every harness on your machine.

A single foreground process that routes MCP tool calls from any harness (Claude Code, OpenCode, …) to configured MCP servers, with default-deny authz, opt-in interactive approval, a complete audit log, and built-in extensible tools. The hub *is* an MCP server: harnesses connect to it, and it aggregates external MCP servers + built-in tools behind one interface.

## Install & run

Requires Python ≥3.10 and [`uv`](https://docs.astral.sh/uv/) (CI runs on 3.12). From the
repo root:

```bash
uv sync                          # create .venv + install all workspace packages and dev tooling
uv run unified-mcphub start      # that's it — runs in the foreground (ctrl-C to stop)
```

`start` **self-seeds** a working `~/.unified-ai/mcphub/` on first run (config + a `default`
workspace with the bundled servers + the dangerous-commands floor, all mode 0600). Run
`uv run unified-mcphub init` to seed the config without starting (idempotent).

While it's running, drive it from another terminal:

```bash
uv run unified-mcphub list-tools           # built-in__ping (+ any configured server tools)
uv run unified-mcphub audit tail
uv run unified-mcphub install claude-code   # wire a harness (--list / --dry-run)
```

### Wiring a harness — default vs. extra-safe

**Default install** — wires the harness to the hub at `--scope local` (this project only):

```bash
uv run unified-mcphub install claude-code               # this project
uv run unified-mcphub install claude-code --scope user  # all projects (global)
uv run unified-mcphub install opencode
```

This already protects you: the CLI itself masks `Bearer <token>` from its own output (Layer 1,
always on), so the hub auth token never lands in your scrollback, and reinstalling is idempotent
— it removes-then-adds, which **rotates the token in one step**. Add `--dry-run` to preview,
`--list` to see supported harnesses.

**Extra-safe install (claude-code only)** — adds an opt-in defense at the harness layer on top
of the default:

```bash
uv run unified-mcphub install claude-code --with-redaction-hook
```

`--with-redaction-hook` also installs a **user-scope `PreToolUse` hook** (in
`~/.claude/settings.json`, scoped via `if: "Bash(claude mcp *)"`) that pipes the output of any
`claude mcp …` command through a bearer-token redactor — so tokens are scrubbed even when you
(or another tool) run those commands by hand, outside the hub. It degrades to a no-op if `jq`
is absent or the command is already wrapped. Off by default; opt in with the flag. Reverse any
install with `uninstall <harness> [--scope …]`.

### Secret redaction (defense in depth)

Three independent layers, so a leak has to beat all of them:

| Layer | Scope | Default | How to enable |
|---|---|---|---|
| 1 — CLI output masking | the hub's own `claude mcp …` subprocess output | **always on** | — |
| 2 — Claude Code hook | any `claude mcp …` command, hub-run or hand-run | off | `install claude-code --with-redaction-hook` |
| 3 — `redact:` result policy | scrubs tool **results** before they're returned *and* before they're audited | off | uncomment the `redact:` block in your workspace |

Layer 3 is harness-agnostic (every connected harness benefits) and lives in the workspace file.
The seeded `default.yaml` ships it commented-out with a conservative example (bearer tokens only):

```yaml
redact:
  enabled: true
  replacement: "[REDACTED]"
  patterns:
    - "Bearer\\s+[0-9a-fA-F]{16,}"
    # - "sk-[A-Za-z0-9]+"          # add your own API-key shapes
```

Patterns are regexes. Avoid broad ones like bare 64-hex — they'd also mask legitimate sha256
digests that appear in tool output.

## Workspaces & config

The seeded `default` workspace enables the five bundled light/safe servers (`filesystem`,
`shell`, `fetch`, `python`, `documents`) and no third-party upstreams, so it runs anywhere. To
add servers, edit `~/.unified-ai/mcphub/workspaces/default.yaml` — it ships with commented
examples for stdio `command:` and HTTP `url:` upstreams + rules (container `image:` is M0.5).

## Develop

```bash
uv run ruff format --check packages   # formatting (CI gate)
uv run ruff check packages            # lint (CI gate)
uv run pytest packages                # tests (CI gate)
```

These three are exactly what the `lint-and-test` CI job runs on every PR; `main` is protected
and won't accept a merge until they pass.

## Architecture & internals

### Source of truth

- **Spec:** [`../../specs/mcphub/m0.v1.md`](../../specs/mcphub/m0.v1.md) — the complete technical spec. Build from this.
- **Design:** [`../../docs/milestones/m0-local-mcp-hub.md`](../../docs/milestones/m0-local-mcp-hub.md)
- **ADRs:** 0006 (authz), 0008 (trace allowlist), 0009 (audit), 0013 (discovery), 0018 (prompts), 0019 (M0/M0.5 split), 0020 (cross-path policy) — all `Accepted`. Packaging: 0023 (MCP client shared package).

### Module map

| Module | Spec § | Purpose |
|---|---|---|
| `cli.py` | §13 | CLI entry (`unified-mcphub ...`) |
| `config.py` | §2 | `config.yaml` + workspaces + `dangerous-commands.yaml` loading; file-watch reload |
| `hub.py` | §8, §10 | Foreground hub: bind transports, supervise servers, serve as MCP server, aggregate tools |
| `supervisor.py` | §8 | Per-server supervisor (spawn/connect, exponential backoff, health) — composes `unified-mcp-client` |
| `transports.py` | §3.1 | Unix socket (primary) + TCP loopback (fallback) |
| `authz.py` | §4 | Policy resolver: precedence (exact rule > danger floor > wildcard > implicit deny) |
| `approval.py` | §5 | In-process TUI prompt (decisions only from hub's own terminal) |
| `audit.py` | §6 | Two-phase append-only audit log writer + reader + `audit` CLI subcommands |
| `secrets.py` | §9 | Encrypted secrets store (OS keyring) + `secrets` CLI |
| `oauth.py` | §3.4 | Upstream OAuth (Auth Code + PKCE) |
| `tools.py` | §10 | Built-in tool discovery (`~/.unified-ai/mcphub/tools/*.py` + in-tree registry) |
| `sandbox.py` | §7 | Containerized MCP server sandboxing + image-digest pinning + Sigstore |
| `discovery.py` | §12 | `~/.unified-ai/discovery/daemons.json` writer/reader |
| `installers/` | §11 | `install <harness>` — claude-code + opencode at M0; pluggable |

### Key early decision (MCP-HUB-1) — RESOLVED (see [ADR-0023](../../docs/adrs/0023-mcp-client-shared-package.md))

The hub needs an MCP **client** to talk OUT to external servers. The existing client at
`src/unified_orchestrator/tools/mcp/` is **synchronous** (blocking `subprocess` + `select`),
**STDIO-only** (HTTP/SSE are unimplemented stubs, but workspaces reference HTTP upstreams),
and tightly coupled to orchestrator concepts (`converter → ToolDefinition`, `UnifiedToolRegistry`).
Only `config.py`+`server.py` are orchestrator-free — exactly the part that would need an async +
HTTP rewrite — so reusing it is illusory.

**Decision: a standalone `packages/unified-mcp-client/` package**, async, built on the official
`mcp` SDK (stdio + streamable-HTTP). It reuses `mcp.types.Tool` as the interchange type (no parallel
tool model). The hub depends on it now; `adapter-base.self.mcp` reuses it at M1 (ADR-0016) — so it's
extracted where the API seam is already frozen by the MCP spec and a second consumer is specced.

`ToolDefinition` stays an agent-runtime type; the hub operates at the **MCP `Tool` narrow waist**.
Built-ins use a hub-local `@tool` decorator (`tools.py`); the orchestrator's `UnifiedToolRegistry`
is an *optional* bridge, never a hard dep. The per-server **supervisor** (lifecycle/backoff/health)
stays hub-local and composes a client connection.

Audit (ADR-0009), authz resolver (ADR-0006), and discovery (ADR-0013) are built hub-local at M0 to
their ADR schemas, kept self-contained, and lifted into `packages/adapter-common/` at M1 when
`adapter-base` becomes the second consumer.

The hub's own MCP server surface (what harnesses connect to) is a small hand-rolled
JSON-RPC-over-HTTP endpoint served by FastAPI/uvicorn on the Unix socket + TCP — full control over
caller-id, authz, and audit on the hot path.
