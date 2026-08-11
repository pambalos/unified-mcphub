"""Unit tests for approval decision logic — spec §5, ADR-0018 + ADR-0025.

Covers the master switch and the background fail-safe (the security-critical
paths) and the two argument-scoped allow-always variants. The interactive
keypress reader is driven via a patched stdin.
"""

from __future__ import annotations

import io

import pytest

from unified_mcphub.approval import (
    Approval,
    TerminalChannel,
    build_arg_filter,
    default_prefix,
    primary_arg,
)

SHELL = "mcp://shell/execute_command"
ARGS = {"command": "git status"}


# --- pure helpers -------------------------------------------------------------


def test_primary_arg_prefers_known_names():
    assert primary_arg({"command": "ls", "timeout": 5}) == "command"
    assert primary_arg({"url": "http://x", "allow_blocked": True}) == "url"
    assert primary_arg({"path": "/tmp/x"}) == "path"


def test_primary_arg_falls_back_to_sole_string_arg():
    assert primary_arg({"weird_name": "value"}) == "weird_name"


def test_primary_arg_none_when_ambiguous_or_absent():
    assert primary_arg({}) is None
    assert primary_arg({"a": "x", "b": "y"}) is None  # two strings, not in known list
    assert primary_arg({"count": 3, "flag": True}) is None  # no string args


def test_default_prefix_is_first_token_with_space():
    assert default_prefix("git push --force") == "git "
    assert default_prefix("ls") == "ls"


def test_build_arg_filter_exact_and_prefix():
    assert build_arg_filter("command", "git status", prefix=False) == {
        "command": {"equals": ["git status"]}
    }
    assert build_arg_filter("command", "git ", prefix=True) == {
        "command": {"starts_with": ["git "]}
    }


# --- master switch / fail-safe (unchanged) ------------------------------------


@pytest.mark.asyncio
async def test_master_switch_off_auto_allows():
    outcome = await Approval(enabled=False, channel=TerminalChannel()).resolve(
        SHELL, "c", "s", ARGS
    )
    assert outcome.allowed
    assert outcome.authz_decision == "approval_disabled"


@pytest.mark.asyncio
async def test_background_hub_fails_safe_to_deny():
    outcome = await Approval(enabled=True, channel=None).resolve(SHELL, "c", "s", ARGS)
    assert not outcome.allowed
    assert outcome.authz_decision == "prompt_denied"
    assert outcome.reason == "no_approval_channel"


@pytest.mark.asyncio
async def test_session_allow_remembered(monkeypatch):
    """A session grant must satisfy the next call without re-prompting.

    Asserted through behaviour rather than the cache itself: stdin holds a
    single `s`, so a second prompt would read EOF and deny.
    """
    monkeypatch.setattr("sys.stdin", io.StringIO("s\n"))
    appr = Approval(enabled=True, channel=TerminalChannel())
    assert (await appr.resolve(SHELL, "c", "s", ARGS)).allowed
    outcome = await appr.resolve(SHELL, "c", "s", ARGS)
    assert outcome.allowed and outcome.session
    assert outcome.decided_by == "session"


# --- keypress decisions -------------------------------------------------------


@pytest.mark.asyncio
async def test_keypress_allow_once_not_persistent(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("a\n"))
    outcome = await Approval(enabled=True, channel=TerminalChannel()).resolve(SHELL, "c", "s", ARGS)
    assert outcome.allowed and not outcome.persistent and outcome.args_filter is None


@pytest.mark.asyncio
async def test_keypress_allow_always_command_scopes_to_exact_value(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("c\n"))
    outcome = await Approval(enabled=True, channel=TerminalChannel()).resolve(SHELL, "c", "s", ARGS)
    assert outcome.allowed and outcome.persistent
    assert outcome.args_filter == {"command": {"equals": ["git status"]}}


@pytest.mark.asyncio
async def test_keypress_allow_always_prefix_default(monkeypatch):
    # 'p' then an empty line -> accept the default prefix ('git ').
    monkeypatch.setattr("sys.stdin", io.StringIO("p\n\n"))
    outcome = await Approval(enabled=True, channel=TerminalChannel()).resolve(SHELL, "c", "s", ARGS)
    assert outcome.allowed and outcome.persistent
    assert outcome.args_filter == {"command": {"starts_with": ["git "]}}


@pytest.mark.asyncio
async def test_keypress_allow_always_prefix_typed(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("p\ngit log \n"))
    outcome = await Approval(enabled=True, channel=TerminalChannel()).resolve(SHELL, "c", "s", ARGS)
    assert outcome.args_filter == {"command": {"starts_with": ["git log "]}}


@pytest.mark.asyncio
async def test_command_always_with_no_scopeable_arg_degenerates_to_tool(monkeypatch):
    # No primary string arg -> 'c' allows the whole tool, transparently (ADR-0025).
    monkeypatch.setattr("sys.stdin", io.StringIO("c\n"))
    outcome = await Approval(enabled=True, channel=TerminalChannel()).resolve(
        "mcp://built-in/refresh", "c", "s", {}
    )
    assert outcome.allowed and outcome.persistent and outcome.args_filter is None


@pytest.mark.asyncio
async def test_floor_prompt_warns_on_scoped_allow(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("c\n"))
    await Approval(enabled=True, channel=TerminalChannel()).resolve(
        SHELL, "c", "s", ARGS, floored=True
    )
    assert "danger floor" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_keypress_deny_always_is_persistent_tool_wide(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("D\n"))
    outcome = await Approval(enabled=True, channel=TerminalChannel()).resolve(SHELL, "c", "s", ARGS)
    assert not outcome.allowed and outcome.persistent
    assert outcome.args_filter is None  # deny stays tool-wide


@pytest.mark.asyncio
async def test_unknown_keypress_defaults_to_deny(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("z\n"))
    outcome = await Approval(enabled=True, channel=TerminalChannel()).resolve(SHELL, "c", "s", ARGS)
    assert not outcome.allowed


@pytest.mark.asyncio
async def test_session_allow_does_not_leak_to_another_tool(monkeypatch):
    """The grant is scoped to the tool it was given for."""
    monkeypatch.setattr("sys.stdin", io.StringIO("s\n"))
    appr = Approval(enabled=True, channel=TerminalChannel())
    assert (await appr.resolve(SHELL, "c", "s", ARGS)).allowed
    # stdin is exhausted, so a fresh prompt reads EOF and denies.
    other = await appr.resolve("mcp://shell/other_tool", "c", "s", ARGS)
    assert not other.allowed


@pytest.mark.asyncio
async def test_a_broken_channel_denies_rather_than_raising():
    """UAI-133: a channel that cannot reach an operator raises, and the engine
    turns that into a deny — previously the exception escaped into the call
    path, which is a 500 where a refusal belongs."""

    class Broken:
        async def ask(self, *_args):
            raise RuntimeError("discord bridge down")

    outcome = await Approval(enabled=True, channel=Broken()).resolve(SHELL, "c", "s", ARGS)
    assert not outcome.allowed
    assert outcome.authz_decision == "prompt_denied"
    assert outcome.reason == "approval_channel_error"
