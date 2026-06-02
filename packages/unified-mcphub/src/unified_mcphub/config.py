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


class Upstream(BaseModel):
    """How to reach an external MCP server. stdio (command) | http (url) | image (M0.5)."""

    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    image: str | None = None


class OAuthConfig(BaseModel):
    authorize_url: str
    token_url: str
    client_id: str
    scopes: list[str] = Field(default_factory=list)


class ServerSpec(BaseModel):
    upstream: Upstream
    auth_secret_ref: str | None = None
    oauth: OAuthConfig | None = None
    enabled: bool = True  # flip to false to disable a package without deleting its entry


class Rule(BaseModel):
    tool: str                                   # mcp:// URI pattern, * wildcards
    callers: list[str] | None = None            # None = any caller
    # Per-argument operator map (ADR-0006): {arg_name: {equals|starts_with|matches: [values]}}
    args_filter: dict[str, dict[str, list[str]]] | None = None
    effect: str                                 # allow | deny | prompt
    audit_level: str = "standard"


class Authz(BaseModel):
    rules: list[Rule] = Field(default_factory=list)


class Workspace(BaseModel):
    servers: dict[str, ServerSpec] = Field(default_factory=dict)
    authz: Authz = Field(default_factory=Authz)


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


def load_workspace(name: str) -> Workspace:
    path = workspace_path(name)
    if not path.exists():
        raise FileNotFoundError(f"workspace '{name}' not found at {path}")
    return Workspace.model_validate(_read_yaml(path))


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
