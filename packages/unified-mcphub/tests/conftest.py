"""Shared pytest fixtures for unified-mcphub.

`hub_home` isolates ~/.unified-ai under a tmp dir and seeds a starter workspace
(a `filesystem` server backed by the stdio fake at tests/fixtures/) +
dangerous-commands.yaml, all at the modes the hub enforces.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest
import yaml

import unified_mcphub.secrets as secrets_mod

FIXTURES = Path(__file__).parent / "fixtures"
FAKE_SERVER = FIXTURES / "fake_mcp_server.py"


@pytest.fixture
def hub_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("UNIFIED_HOME", str(tmp_path / ".unified-ai"))

    home = tmp_path / ".unified-ai" / "mcphub"
    (home / "workspaces").mkdir(parents=True)
    os.chmod(home, 0o700)

    # AF_UNIX paths are capped (~104 chars on macOS); the deep pytest tmp dir
    # blows that, so keep the socket in a short temp dir. Real ~/.unified-ai is short.
    sock_dir = Path(tempfile.mkdtemp(prefix="umh-"))
    sock_path = sock_dir / "h.sock"

    (home / "config.yaml").write_text(
        textwrap.dedent(
            f"""
            listen:
              unix_socket: {sock_path}
              tcp: null
            approval:
              enabled: true
            active_workspace: default
            """
        ).strip()
        + "\n"
    )
    os.chmod(home / "config.yaml", 0o600)

    (home / "workspaces" / "default.yaml").write_text(
        textwrap.dedent(
            f"""
            servers:
              filesystem:
                upstream:
                  command: {sys.executable}
                  args: ["{FAKE_SERVER}"]
            authz:
              rules:
                - tool: "mcp://*/list_*"
                  effect: allow
            """
        ).strip()
        + "\n"
    )
    os.chmod(home / "workspaces" / "default.yaml", 0o600)

    (home / "dangerous-commands.yaml").write_text("require_approval: []\n")
    os.chmod(home / "dangerous-commands.yaml", 0o600)

    yield home
    shutil.rmtree(sock_dir, ignore_errors=True)


@pytest.fixture
def enable_tcp(hub_home):
    """Turn on the TCP transport in the seeded config (preserving the socket)."""
    def _enable(tcp: str = "127.0.0.1:7712") -> None:
        config = hub_home / "config.yaml"
        data = yaml.safe_load(config.read_text())
        data.setdefault("listen", {})["tcp"] = tcp
        config.write_text(yaml.safe_dump(data, sort_keys=False))

    return _enable


@pytest.fixture
def fake_keyring(monkeypatch):
    """In-memory keyring so secrets tests never touch the real OS keyring."""
    backing: dict = {}
    monkeypatch.setattr(secrets_mod.keyring, "get_password", lambda s, u: backing.get((s, u)))
    monkeypatch.setattr(
        secrets_mod.keyring, "set_password", lambda s, u, v: backing.__setitem__((s, u), v)
    )
    return backing
