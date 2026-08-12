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
`shell`, `fetch`, `python`, `documents`) and no third-party upstreams, so it runs anywhere. A
workspace file (`~/.unified-ai/mcphub/workspaces/<name>.yaml`) has two parts: a `servers:` map
(what to run) and an `authz.rules:` list (what each caller may invoke). **Default-deny is
implicit** — anything not matched by an `allow`/`prompt` rule is denied. The seeded
`default.yaml` ships commented stdio + HTTP server templates you can copy.

## Adding MCP servers

### The easy path — `add-server`

```bash
uv run unified-mcphub add-server memory --npx '@modelcontextprotocol/server-memory@2025.4.0'
```

This writes the server into the active workspace, **probes it once** to list its tools, and
**proposes authz rules** from a name heuristic — then you confirm. A running hub picks the change
up live (file-watch reload); no restart. Useful flags:

| Flag | Effect |
|---|---|
| `--npx PKG` / `--uvx PKG` | shorthand for a Node / Python stdio server (`npx -y PKG` / `uvx PKG`) |
| `--command CMD --arg …` | a raw stdio command (the blessed path — see Supply chain below) |
| `--url URL [--auth-secret-ref NAME]` | a remote streamable-HTTP server (Bearer from the secrets store) |
| `--configure-perms` | step through each tool and set its permission by hand (Enter = the heuristic default) |
| `--no-probe` | don't connect; write the entry with no rules |
| `--dry-run` | print the resulting workspace YAML, write nothing |
| `--allow-unpinned` | opt this server out of version-pinning (see below) |
| `--yes` / `--force` | non-interactive / overwrite an existing entry |

Reverse it with `uv run unified-mcphub remove-server memory` (deletes the entry **and** the rules
scoped to it, after a confirmation; shared `mcp://*/…` wildcards are left alone).

#### How rules are proposed (three tiers)

The probe classifies each tool by name into a default effect, written as an explicit
server-scoped rule (`mcp://NAME/tool`) so the workspace stays self-documenting. A verb
is matched at **either** the leading or trailing word boundary, so both `read_graph`
and `hub_repo_search` (the `<noun>_<verb>` shape many remote servers use) are caught:

| Tier | Matches (verb at either end) | Default effect |
|---|---|---|
| reads | `read list get search find query fetch` | **allow** |
| mutations | `create add update edit write set execute run generate …` | **prompt** |
| destructive | `delete remove drop destroy` | **deny** (fail closed) |
| anything else | (unrecognized) | **prompt** (safe default — review these) |

Destructive tools are denied by default and never silently reachable; flip the rule to
`prompt`/`allow` (or use `--configure-perms`) to opt in.

### The manual path — edit the workspace YAML

`add-server` just edits the file; you can too. Append under `servers:` and add matching rules.
Three upstream kinds:

```yaml
servers:
  memory:                                   # stdio (Node, via npx)
    enabled: true
    upstream:
      command: npx
      args: ["-y", "@modelcontextprotocol/server-memory@2025.4.0"]
      env: { MEMORY_FILE_PATH: "~/.unified-ai/memory.json" }
  remote-thing:                             # remote streamable-HTTP
    enabled: true
    upstream: { url: "https://mcp.example.com/v1" }
    auth_secret_ref: remote-thing-token     # `secrets set remote-thing-token` first
authz:
  rules:
    - tool: "mcp://memory/read_graph"
      effect: allow
    - tool: "mcp://memory/delete_entities"
      effect: deny
```

Container (`image:`) upstreams arrive at M0.5. A bare `python`/`python3` command resolves to the
hub's own interpreter; any other command (`npx`, `uvx`, an absolute path) must be on `PATH`.

### Distribution methods

The MCP ecosystem ships servers in four shapes, all expressible here:

| Shape | Config | Notes |
|---|---|---|
| Node (npx) | `command: npx`, `args: ["-y", "pkg@ver"]` | the most common |
| Python (uvx) | `command: uvx`, `args: ["pkg==ver"]` | |
| container | `image: …` | M0.5 (digest-pinned + Sigstore) |
| remote | `url: …` + `auth_secret_ref`/`oauth` | no local runtime needed |

### Authenticating a remote server

Store the credential once (`secrets set <name>`), then reference it. Three shapes:

```sh
# 1) Bearer token (the common case — e.g. Hugging Face: Authorization: Bearer hf_…)
secrets set hf-token
add-server hf --url https://huggingface.co/mcp --auth-secret-ref hf-token

# 2) Custom API-key header (e.g. Context7: CONTEXT7_API_KEY: <key>) — empty scheme = raw value
secrets set c7
add-server context7 --url https://mcp.context7.com/mcp \
  --auth-secret-ref c7 --auth-header CONTEXT7_API_KEY --auth-scheme ''

# 3) OAuth — interactive login. Modern remote servers use Dynamic Client Registration:
#    give just the issuer in the workspace `oauth:` block and `auth login` discovers the
#    endpoints + registers a client automatically (no pre-registered client_id needed).
auth login linear
```

`--auth-header` defaults to `Authorization` and `--auth-scheme` to `Bearer`; pass
`--auth-scheme ''` to send the secret as the raw header value. OAuth config (static
`authorize_url`/`token_url`/`client_id`, or DCR via `issuer`) lives in the workspace
`oauth:` block. After `auth login`, the hub **refreshes the access token on every
(re)connect** and sends it as `Authorization: Bearer <token>`, persisting any rotated
refresh token — so an expired token self-heals on the next reconnect. Until you log
in, an `oauth:` server connects with no auth (and the log points you to `auth login`).

### The master key & where it lives

Every secret above is stored encrypted in `~/.unified-ai/mcphub/secrets.enc`. The
**only** thing kept outside that file is the Fernet master key that decrypts it.
Where that key lives is set by `secrets.key_backend` in `config.yaml`:

| Backend | Key location | Prompts? | Use when |
|---|---|---|---|
| `keyring` | OS keychain (macOS Keychain / Win DPAPI / Linux Secret Service) | macOS may prompt once/run | desktop, most secure at rest |
| `file` | `~/.unified-ai/mcphub/secrets.key` (`0600`) | never | headless Linux / containers (no Secret Service) |
| `env` | `$UNIFIED_MCPHUB_SECRETS_KEY` | never | CI / automation |
| `auto` *(default)* | env-if-set → keychain on macOS/Win → Linux keychain if present, else file | per resolved backend | leave it; it just works per-platform |

The key is **read once per process** (memoized), so the backend — and any macOS
keychain prompt — is hit at most once per run, not once per server. At start the hub
logs the credential names it will read and, in the default `access_mode: prompt`,
waits for a single `y/N` before unlocking (set `access_mode: auto` to skip — required
for headless, where `prompt` fails fast for lack of a TTY).

The key **is** the lock on `secrets.enc`, so switching backends means moving the same
key, not re-entering every secret:

```sh
secrets key migrate --to file      # keychain → 0600 key file (then set key_backend: file)
secrets key migrate --to env       # prints the `export …` line for $UNIFIED_MCPHUB_SECRETS_KEY
secrets key export                 # print the current key   ·   secrets key import  # store one
```

### Supply chain & version pinning

`npx -y pkg` / `uvx pkg` **download and run remote code at startup** — *upstream* of the hub's
call-time gating. So pin, or better, don't fetch at all. The hardening ladder:

1. **unpinned `@latest`** — worst; **refused by default** (see below).
2. **pinned version** (`pkg@1.2.3`, `pkg==1.2.3`) — a **drift guard**: no silent pickup of a
   freshly-published / hijacked release. Still fetches-and-runs; doesn't protect against a
   malicious *pinned* package. This is what the policy enforces — necessary, not sufficient.
3. **integrity/hash pinning** — pin the exact artifact, not just the version string.
4. **pre-install + point at the binary** (`uv tool install …` / `npm i -g …`, then
   `--command <binary>`) — **no network at startup**, fully auditable. The gold standard.

`require_pinned_versions: true` (in `config.yaml`, **on by default**) refuses to start an
unpinned fetch-and-run upstream — both at `add-server` time and on hub load. It's the stdio
analog of M0.5's image-digest pinning: one "pin your upstreams" policy. Opt a single server out
with `allow_unpinned: true` (or `--allow-unpinned`) when it genuinely only ships `@latest` or a
git ref; set the global to `false` to disable the policy entirely.

### Verify

```bash
uv run unified-mcphub list-servers     # configured servers + kind
uv run unified-mcphub list-tools       # tools the running hub aggregates
uv run unified-mcphub audit tail       # watch decisions as calls come in
```

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
| `secrets.py` | §9 | Encrypted secrets store + pluggable master-key backend (keyring/file/env) + `secrets` CLI |
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
