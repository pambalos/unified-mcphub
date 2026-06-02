"""Unit tests for config loading — spec §2."""

from __future__ import annotations

import stat
import textwrap
from pathlib import Path

import pytest

from unified_mcphub.config import (
    ListenConfig,
    bootstrap,
    config_path,
    load_config,
    mcphub_home,
)


def test_bootstrap_seeds_runnable_defaults(tmp_path, monkeypatch):
    # Fresh machine (no hub_home seeding): bootstrap must make the hub loadable.
    monkeypatch.setenv("UNIFIED_HOME", str(tmp_path / ".unified-ai"))
    created = bootstrap()
    assert config_path() in created
    assert stat.S_IMODE(config_path().stat().st_mode) == 0o600

    cfg = load_config()  # would raise if anything were missing
    assert cfg.workspace_name == "default"
    # Working default: the five bundled light/safe servers, all enabled.
    assert set(cfg.workspace.servers) == {"filesystem", "shell", "fetch", "python", "documents"}
    assert all(s.enabled for s in cfg.workspace.servers.values())
    assert all(s.upstream.command == "python" for s in cfg.workspace.servers.values())

    assert bootstrap() == []  # idempotent


def test_seed_listen_resolves_under_unified_home(tmp_path, monkeypatch):
    # Regression: a temp-$UNIFIED_HOME hub must NOT inherit the real ~ socket/port.
    # The seed omits listen.*, so ListenConfig defaults resolve under $UNIFIED_HOME.
    home = tmp_path / ".unified-ai"
    monkeypatch.setenv("UNIFIED_HOME", str(home))
    bootstrap()
    listen = load_config().hub.listen

    sock = Path(listen.unix_socket)
    assert sock == home / "mcphub" / "mcphub.sock"
    assert str(Path.home()) not in str(sock)  # never the real home
    # TCP stays on by default (HTTP installers need it) at the default port.
    assert listen.tcp_enabled is True
    assert listen.tcp_address == "127.0.0.1:7712"


def test_listen_tcp_address_toggles_with_enabled():
    assert ListenConfig(port=7799).tcp_address == "127.0.0.1:7799"
    assert ListenConfig(tcp_enabled=False).tcp_address is None


def test_load_defaults(hub_home):
    cfg = load_config()
    assert cfg.workspace_name == "default"
    assert cfg.hub.approval.enabled is True
    assert cfg.hub.audit.retention_days == 365  # model default
    assert "filesystem" in cfg.workspace.servers
    assert cfg.workspace.servers["filesystem"].upstream.command is not None


def test_seeded_danger_floor_targets_real_shell_tool(tmp_path, monkeypatch):
    # Regression: the seeded dangerous-shell floor must use the bundled shell
    # tool's real name (`execute_command`), not `exec`. The floor is the safety
    # net under a catch-all/sandbox allow (an explicit exact rule intentionally
    # beats the floor) — so a `mcp://*/*` allow must still floor rm -rf/sudo.
    monkeypatch.setenv("UNIFIED_HOME", str(tmp_path / ".unified-ai"))
    bootstrap()
    cfg = load_config()

    from unified_mcphub.authz import AuthzResolver, Effect
    from unified_mcphub.config import Authz, Rule, Workspace

    sandbox = Workspace(authz=Authz(rules=[Rule(tool="mcp://*/*", effect="allow")]))
    r = AuthzResolver(sandbox, cfg.dangerous)
    for cmd in ("rm -rf /x", "sudo whoami", "git push --force origin main"):
        d = r.resolve("mcp://shell/execute_command", {"command": cmd}, "claude-code")
        assert d.effect is Effect.PROMPT and d.source == "danger_floor", (cmd, d)
    safe = r.resolve("mcp://shell/execute_command", {"command": "ls -la"}, "claude-code")
    assert safe.effect is Effect.ALLOW  # benign command still allowed by the catch-all


def test_env_home_resolution(hub_home):
    # mcphub_home() resolves under the test's $UNIFIED_HOME, not the real ~.
    assert mcphub_home() == hub_home


def test_dangerous_defaults_empty(hub_home):
    assert load_config().dangerous.require_approval == []


def test_workspace_override(hub_home):
    (hub_home / "workspaces" / "personal.yaml").write_text(
        textwrap.dedent(
            """
            servers: {}
            authz:
              rules:
                - tool: "mcp://*/*"
                  effect: allow
            """
        ).strip()
        + "\n"
    )
    cfg = load_config("personal")
    assert cfg.workspace_name == "personal"
    assert cfg.workspace.servers == {}
    assert cfg.workspace.authz.rules[0].effect == "allow"


def test_missing_workspace_raises(hub_home):
    with pytest.raises(FileNotFoundError):
        load_config("does-not-exist")
