"""install --dry-run prints intended changes without writing (spec §11, §16)."""

from __future__ import annotations

from pathlib import Path

import pytest

from unified_mcphub import installers
from unified_mcphub.config import mcphub_home
from unified_mcphub.installers import _common



def test_dry_run_merge_writes_nothing(hub_home, enable_tcp, monkeypatch, capsys):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)

    installers.dispatch_install("claude-code", dry_run=True)
    assert "[dry-run]" in capsys.readouterr().out
    assert not (Path.home() / ".claude.json").exists()
    assert not (mcphub_home() / "caller-tokens").exists()  # no token minted on dry-run


def test_dry_run_cli_path_prints_command(hub_home, enable_tcp, monkeypatch, capsys):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: True)

    installers.dispatch_install("claude-code", dry_run=True)
    assert "[dry-run] would run: claude mcp add" in capsys.readouterr().out


def test_unknown_harness_exits(hub_home):
    with pytest.raises(SystemExit):
        installers.dispatch_install("aider")
