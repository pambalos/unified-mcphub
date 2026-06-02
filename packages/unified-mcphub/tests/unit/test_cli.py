"""CLI parser + dispatch wiring (spec §13)."""

from __future__ import annotations

import pytest

from unified_mcphub.cli import build_parser, main


def test_start_parses_workspace_flag():
    args = build_parser().parse_args(["start", "--workspace", "work"])
    assert args.command == "start"
    assert args.workspace == "work"


def test_install_list(capsys):
    assert main(["install", "--list"]) == 0
    out = capsys.readouterr().out
    assert "claude-code" in out and "opencode" in out


def test_install_unknown_harness_exits():
    with pytest.raises(SystemExit):
        main(["install", "aider"])


def test_install_requires_harness_or_list():
    with pytest.raises(SystemExit):
        main(["install"])


def test_init_seeds_config(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("UNIFIED_HOME", str(tmp_path / ".unified-ai"))
    assert main(["init"]) == 0
    assert "created" in capsys.readouterr().out
    assert main(["init"]) == 0  # idempotent
    assert "already initialized" in capsys.readouterr().out


def test_missing_subcommand_exits():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
