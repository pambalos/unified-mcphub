"""CLI parser + dispatch wiring (spec §13)."""

from __future__ import annotations

import pytest

import unified_mcphub.cli as cli
from unified_mcphub.cli import build_parser, main
from unified_mcphub.transports import PortInUseError


def test_start_parses_workspace_flag():
    args = build_parser().parse_args(["start", "--workspace", "work"])
    assert args.command == "start"
    assert args.workspace == "work"


def test_start_parses_port():
    args = build_parser().parse_args(["start", "--port", "7799"])
    assert args.port == 7799
    assert args.no_tcp is False


def test_start_parses_no_tcp():
    args = build_parser().parse_args(["start", "--no-tcp"])
    assert args.no_tcp is True
    assert args.port is None


def test_start_port_and_no_tcp_are_mutually_exclusive():
    # Clear behaviour over silent reconciliation: passing both is an error.
    with pytest.raises(SystemExit):
        build_parser().parse_args(["start", "--port", "7799", "--no-tcp"])


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


def test_start_port_in_use_prints_friendly_error(monkeypatch, capsys):
    async def _boom(*args, **kwargs):
        raise PortInUseError(7712)

    monkeypatch.setattr(cli, "run", _boom)
    assert main(["start", "--port", "7712"]) == 1  # clean non-zero exit
    err = capsys.readouterr().err
    assert "7712 in use" in err and "--port" in err
    assert "Traceback" not in err  # one line, no traceback


def test_missing_subcommand_exits():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
