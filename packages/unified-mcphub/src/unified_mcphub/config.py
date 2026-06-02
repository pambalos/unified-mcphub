"""Config loading — spec §2.

- Hub-global `config.yaml` (transport, audit, approval, active_workspace)
- Per-workspace `workspaces/<name>.yaml` (servers + authz.rules)
- Global `dangerous-commands.yaml` (the safety floor)

Default-deny is implicit and not configurable (no `default:` field, no
`allow_unsafe_default`). Paths resolve from $UNIFIED_HOME (test isolation) or
`~/.unified-ai`. File-watch reload lives in hub.py (spec §8).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .util import secure_write

_DEFAULTS_DIR = Path(__file__).parent / "defaults"


# --- paths (resolved lazily so tests can repoint $HOME / $UNIFIED_HOME) -------


def unified_home() -> Path:
    env = os.environ.get("UNIFIED_HOME")
    return Path(env) if env else Path.home() / ".unified-ai"


def mcphub_home() -> Path:
    return unified_home() / "mcphub"


def config_path() -> Path:
    return mcphub_home() / "config.yaml"


def workspace_path(name: str) -> Path:
    return mcphub_home() / "workspaces" / f"{name}.yaml"


def workspace_local_path(name: str) -> Path:
    """Machine-managed learned-rules file (ADR-0024) beside the curated workspace."""
    return mcphub_home() / "workspaces" / f"{name}.local.yaml"


def dangerous_commands_path() -> Path:
    return mcphub_home() / "dangerous-commands.yaml"


def audit_dir() -> Path:
    return mcphub_home() / "audit"


def discovery_path() -> Path:
    return unified_home() / "discovery" / "daemons.json"


def canonical_truth_path() -> Path:
    return mcphub_home() / "unified-mcp.json"


# --- models (spec §2) ---------------------------------------------------------


class ListenConfig(BaseModel):
    unix_socket: str = Field(default_factory=lambda: str(mcphub_home() / "mcphub.sock"))
    tcp: str | None = "127.0.0.1:7712"


class AuditConfig(BaseModel):
    retention_days: int = 365


class ApprovalConfig(BaseModel):
    enabled: bool = True


class HubConfig(BaseModel):
    listen: ListenConfig = Field(default_factory=ListenConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    active_workspace: str = "default"
    # Supply-chain safety floor: refuse to stand up an unpinned fetch-and-run
    # upstream (`npx -y pkg`, bare `uvx pkg`). A *drift guard* — it stops silent
    # pickup of a freshly-published / hijacked `@latest`; it does NOT stop
    # fetch-and-run itself (pre-install + point at a binary for that). The stdio
    # analog of image-digest pinning. Per-server `allow_unpinned: true` opts out.
    require_pinned_versions: bool = True


class Upstream(BaseModel):
    """How to reach an external MCP server. stdio (command) | http (url) | image (M0.5)."""

    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    image: str | None = None


class OAuthConfig(BaseModel):
    # Static registration: provide all three for a pre-registered OAuth client.
    authorize_url: str | None = None
    token_url: str | None = None
    client_id: str | None = None
    # Dynamic Client Registration (RFC 8414/7591): give `issuer` and the endpoints
    # are discovered + a client is registered on first `auth login` (the modern
    # remote-MCP path — e.g. Linear). `registration_url` overrides discovery.
    issuer: str | None = None
    registration_url: str | None = None
    scopes: list[str] = Field(default_factory=list)


class ServerSpec(BaseModel):
    upstream: Upstream
    auth_secret_ref: str | None = None
    # Header to carry the `auth_secret_ref` value on an HTTP upstream. Defaults
    # suit a bearer server (`Authorization: Bearer <secret>`). For an API-key
    # server that uses a custom header, set `auth_header` (e.g. `X-API-Key`,
    # `CONTEXT7_API_KEY`) and `auth_scheme: null` to send the raw secret value.
    auth_header: str = "Authorization"
    auth_scheme: str | None = "Bearer"
    oauth: OAuthConfig | None = None
    enabled: bool = True  # flip to false to disable a package without deleting its entry
    # Explicit, audited opt-out of `require_pinned_versions` for this one server
    # (e.g. it only ships `@latest` or a git ref). Mirrors the `allow_blocked`
    # fetch override: a deliberate escape hatch, not a default.
    allow_unpinned: bool = False


class Rule(BaseModel):
    tool: str  # mcp:// URI pattern, * wildcards
    callers: list[str] | None = None  # None = any caller
    # Per-argument operator map (ADR-0006): {arg_name: {equals|starts_with|matches: [values]}}
    args_filter: dict[str, dict[str, list[str]]] | None = None
    effect: str  # allow | deny | prompt
    audit_level: str = "standard"


class Authz(BaseModel):
    rules: list[Rule] = Field(default_factory=list)


# Conservative default: bearer tokens only. They are unambiguous secrets and the
# pattern (Bearer + 16+ hex) won't collide with legitimate tool output. Broader
# patterns (e.g. bare 64-hex) risk masking real data like sha256 digests, so
# they are left for the operator to opt into per workspace.
_DEFAULT_REDACT_PATTERNS = [r"Bearer\s+[0-9a-fA-F]{16,}"]


class RedactConfig(BaseModel):
    """Scrub secret-shaped strings from tool *results* before they are returned
    to any harness (and before they are written to the audit log). Off by
    default; harness-agnostic when enabled. See spec §10.2 / ADR redaction."""

    enabled: bool = False
    patterns: list[str] = Field(default_factory=lambda: list(_DEFAULT_REDACT_PATTERNS))
    replacement: str = "[REDACTED]"


class Workspace(BaseModel):
    servers: dict[str, ServerSpec] = Field(default_factory=dict)
    authz: Authz = Field(default_factory=Authz)
    redact: RedactConfig = Field(default_factory=RedactConfig)


class DangerousCommands(BaseModel):
    require_approval: list[str] = Field(default_factory=list)


class Config(BaseModel):
    """Everything the hub needs at runtime, loaded together."""

    hub: HubConfig
    workspace_name: str
    workspace: Workspace
    dangerous: DangerousCommands


# --- loaders ------------------------------------------------------------------


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a mapping at the top level")
    return data


def load_hub_config() -> HubConfig:
    return HubConfig.model_validate(_read_yaml(config_path()))


def load_learned_rules(name: str) -> list[dict]:
    """Raw learned-rule dicts from `<name>.local.yaml` (ADR-0024); [] if absent.

    The file is a flat YAML list of exact rules, written by the hub on `*_always`.
    """
    path = workspace_local_path(name)
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list of rules at the top level")
    return data


def load_workspace(name: str) -> Workspace:
    path = workspace_path(name)
    if not path.exists():
        raise FileNotFoundError(f"workspace '{name}' not found at {path}")
    workspace = Workspace.model_validate(_read_yaml(path))
    # Learned rules (ADR-0024) live in a separate machine-managed file and merge
    # as tier-1 exact rules ordered ahead of the curated rules — first-match-wins
    # means they win. The file is absent until the first `*_always`.
    learned = [Rule.model_validate(r) for r in load_learned_rules(name)]
    workspace.authz.rules[:0] = learned
    return workspace


def load_dangerous_commands() -> DangerousCommands:
    return DangerousCommands.model_validate(_read_yaml(dangerous_commands_path()))


def load_config(workspace_override: str | None = None) -> Config:
    hub = load_hub_config()
    name = workspace_override or hub.active_workspace
    return Config(
        hub=hub,
        workspace_name=name,
        workspace=load_workspace(name),
        dangerous=load_dangerous_commands(),
    )


def bootstrap() -> list[Path]:
    """Seed any missing config from packaged defaults (idempotent).

    Makes the hub runnable out of the box: a fresh machine gets a working
    `config.yaml` + `default` workspace + `dangerous-commands.yaml`. Returns the
    files actually created.
    """
    targets = [
        (_DEFAULTS_DIR / "config.yaml", config_path()),
        (_DEFAULTS_DIR / "dangerous-commands.yaml", dangerous_commands_path()),
        (_DEFAULTS_DIR / "default.yaml", workspace_path("default")),
    ]
    created = []
    for source, dest in targets:
        if not dest.exists():
            secure_write(dest, source.read_bytes())
            created.append(dest)
    return created
