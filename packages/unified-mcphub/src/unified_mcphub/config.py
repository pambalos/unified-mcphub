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
from pydantic import BaseModel, Field, field_validator, model_validator

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
    # TCP loopback fallback (the unix socket is the primary, trusted transport).
    # `port` is a first-class field so it is trivial to retarget when 7712 is
    # already taken; `start --port N` / `--no-tcp` override these at launch.
    tcp_enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 7712

    @property
    def tcp_address(self) -> str | None:
        """`host:port` when TCP is enabled, else None (the off switch callers test)."""
        return f"{self.host}:{self.port}" if self.tcp_enabled else None


class AuditConfig(BaseModel):
    retention_days: int = 365


class ApprovalConfig(BaseModel):
    enabled: bool = True
    # Source `prompt` decisions from out-of-process clients (TUI / Discord bridge
    # / web UI) over the local control API when the hub has no terminal. Off -> a
    # headless hub fails closed to deny, as before (UAI-107/109).
    remote: bool = False
    # Seconds to wait for a remote decision before failing closed to deny.
    remote_timeout_s: float = 300.0


class OtelConfig(BaseModel):
    """Decision spans over OTLP — UAI-86 / UAI-116, M0.5 Observability.

    Off by default and non-breaking when off: the disabled telemetry object is
    a no-op and the OpenTelemetry packages are only imported when enabled (they
    live behind the `unified-enforce[otel]` extra, which the hub does not
    require). Telemetry is emitted *after* a verdict, never on the decision
    path.

    The backend is any OTLP/HTTP collector: the embedded Tempo default, or a
    hosted one. For Langfuse (self-hosted or cloud) set `langfuse_host` plus
    the two keys instead of `endpoint` — the OTLP path and Basic-auth header
    are derived from the host, and verdicts map onto
    `langfuse.observation.level`.
    """

    enabled: bool = False
    service_name: str = "unified-mcphub"
    endpoint: str | None = None  # OTLP/HTTP traces endpoint (full URL)
    headers: dict[str, str] = Field(default_factory=dict)
    # Langfuse base URL, e.g. https://cloud.langfuse.com — not the OTLP path.
    langfuse_host: str | None = None
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None


class SecretsConfig(BaseModel):
    """Where the Fernet master key (which decrypts `secrets.enc`) lives, and how
    the hub gates access to it at startup. See spec §9.

    The actual credentials never touch the OS keychain — only this one key does.
    `key_backend` decides where that key is read from; `auto` resolves per-platform
    in secrets.py (env var if set → macOS/Windows keychain → Linux Secret Service if
    present, else a 0600 key file)."""

    # auto | keyring | file | env
    key_backend: str = "auto"
    # prompt | auto — at start the hub logs the credential names it will read, then
    # either waits for a single y/N (prompt) or proceeds (auto). prompt fails fast
    # with no TTY (set `auto` for headless). Gates the hub only, not the CLI.
    access_mode: str = "prompt"
    # `file` backend only: path to the 0600 key file. Defaults beside secrets.enc.
    key_file: str | None = None


_VALID_PROTECTION = {"open", "locked"}
_VALID_RELOAD = {"hot", "manual", "approval"}


class DeploymentConfig(BaseModel):
    """Deployment security profile (UAI-216). Bundles the policy-protection
    controls behind one toggle so a local/dev deployment stays fully open —
    edit and hot-reload policy freely, the current behavior — while a prod
    deployment locks policy against agent tampering.

    The enforcement plane must not be its own bypass: in `open` the operator
    (or an assisting agent) may edit and hot-reload policy at will; in `locked`
    the policy/config dir is write-protected from agent-reachable tools, policy
    file changes do not auto-apply, and constitutional rules the workspace
    cannot override are installed. Everything degrades to today's open behavior
    when `policy_protection` is `open`.
    """

    # open (dev; edit + hot-reload freely) | locked (prod; policy is protected)
    policy_protection: str = "open"
    # hot (apply on file change) | manual (reload only on explicit signal) |
    # approval (staged, applied only after human approval). None → derived from
    # policy_protection: open→hot, locked→approval.
    reload_mode: str | None = None
    # When True in `locked`, refuse to boot if the policy/config dir is writable
    # by the account the MCP servers run as — turning the advisory warning into
    # a hard precondition. Off by default on purpose: the policy-layer controls
    # are defence in depth and the real boundary is filesystem permissions, but
    # refusing to boot would strand a deployment that is locked and correct in
    # every other respect, so enforcing the OS boundary stays opt-in. See
    # docs/deployment-security.md.
    require_protected_config_dir: bool = False

    @property
    def is_locked(self) -> bool:
        return self.policy_protection == "locked"

    def effective_reload_mode(self) -> str:
        """Resolve `reload_mode`, defaulting from the protection profile."""
        if self.reload_mode is not None:
            return self.reload_mode
        return "approval" if self.is_locked else "hot"

    @field_validator("policy_protection")
    @classmethod
    def _check_protection(cls, v: str) -> str:
        if v not in _VALID_PROTECTION:
            raise ValueError(f"policy_protection must be one of {sorted(_VALID_PROTECTION)}")
        return v

    @field_validator("reload_mode")
    @classmethod
    def _check_reload(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_RELOAD:
            raise ValueError(f"reload_mode must be one of {sorted(_VALID_RELOAD)} or null")
        return v

    @model_validator(mode="after")
    def _check_combination(self) -> "DeploymentConfig":
        """`locked` + `hot` is refused rather than quietly honoured.

        Reload-gating is the primary control this profile exists to provide;
        asking for `locked` and then hot-reloading cancels it, leaving a
        deployment that reads as protected in the config file and is not. The
        two ways to mean it are spelled differently: leave `reload_mode` unset
        (locked defaults to `approval`), or say `policy_protection: open`.
        """
        if self.is_locked and self.reload_mode == "hot":
            raise ValueError(
                "policy_protection: locked with reload_mode: hot cancels reload-gating, "
                "the control that makes a locked deployment locked; "
                "omit reload_mode (locked defaults to approval) or use policy_protection: open"
            )
        return self


_VALID_ON_STALE = {"keep", "defer", "deny"}


class ControlPlaneConfig(BaseModel):
    """Join this hub to a fleet (build-04 / build-07).

    Unset (`url` empty) the hub is standalone: its workspace policy decides
    everything and nothing leaves the machine — today's behaviour, unchanged.
    Set, the hub polls the control plane for the signed policy bundle and the
    signed **revocation list**, gates every call on containment *before* its
    workspace policy (a contained agent is contained whatever the rules say),
    ships decision evidence, and cancels a contained principal's calls that are
    already in flight. This is the block that makes the Guardian's "contained
    at its next action" true of a hub, not only of the Envoy sidecar.

    The credential is a secret ref, never a literal: the hub reads it from its
    own secrets store at start-up, alongside the servers' credentials.
    """

    url: str | None = None
    fleet_id: str | None = None
    #: The fleet's pinned root verification key (base64url). Everything the
    #: control plane serves is verified against a chain that ends here; a
    #: hostile or wrong control plane is a refused refresh, not a new policy.
    root_public_key: str | None = None
    credential_secret_ref: str = "control-plane-credential"
    poll_seconds: float = 30.0
    #: What an expired policy bundle does: keep enforcing the old rules
    #: (default), defer everything to a human, or deny everything.
    on_stale: str = "keep"
    #: Where the last verified artifacts are cached, so a restart during an
    #: incident does not become an unprovisioned outage. None → under the hub home.
    cache_dir: str | None = None
    #: Ship decision evidence to the control plane (what the Guardian reads).
    evidence: bool = True
    evidence_interval_seconds: float = 5.0

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    @field_validator("on_stale")
    @classmethod
    def _check_on_stale(cls, v: str) -> str:
        if v not in _VALID_ON_STALE:
            raise ValueError(f"on_stale must be one of {sorted(_VALID_ON_STALE)}")
        return v

    @model_validator(mode="after")
    def _check_complete(self) -> "ControlPlaneConfig":
        if self.enabled and not (self.fleet_id and self.root_public_key):
            raise ValueError(
                "control_plane.url is set but fleet_id and root_public_key are missing; "
                "without the pinned root key nothing the control plane serves can be verified"
            )
        if self.poll_seconds <= 0:
            raise ValueError("control_plane.poll_seconds must be positive")
        if self.evidence_interval_seconds <= 0:
            # `EvidenceShipper` waits this long between flushes; zero is a
            # thread spinning at full tilt against the control plane.
            raise ValueError("control_plane.evidence_interval_seconds must be positive")
        return self


class HubConfig(BaseModel):
    listen: ListenConfig = Field(default_factory=ListenConfig)
    control_plane: ControlPlaneConfig = Field(default_factory=ControlPlaneConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    otel: OtelConfig = Field(default_factory=OtelConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
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
    #: Working directory for a stdio server. Declared rather than inherited: a
    #: relative path argument means nothing without knowing the directory the
    #: process opening it sits in, and "whatever the hub happened to be started
    #: from" is an assumption that holds until someone changes it. None keeps
    #: today's behaviour (inherit the hub's), now as a stated default.
    cwd: str | None = None
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
    #: Argument names this server interprets as filesystem paths. The hub
    #: canonicalises these before deciding and forwards the canonical form, so
    #: the path the policy authorised is the path the server opens. Empty by
    #: default: `path` on some other server may mean a URL path or an object
    #: key, and rewriting that would corrupt the call.
    path_args: list[str] = Field(default_factory=list)


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


def load_secrets_config() -> SecretsConfig:
    """Just the `secrets:` block of config.yaml — read by SecretsStore at the many
    call sites that construct a store without the full Config loaded."""
    return HubConfig.model_validate(_read_yaml(config_path())).secrets


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
