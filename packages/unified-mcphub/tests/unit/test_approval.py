"""Unit tests for approval decision logic — spec §5, ADR-0018 (SEC-MCP-4 logic).

Covers the master switch and the background fail-safe (the security-critical
paths). The interactive keypress reader is driven via a patched stdin.
"""

from __future__ import annotations

import io

import pytest

from unified_mcphub.approval import Approval


@pytest.mark.asyncio
async def test_master_switch_off_auto_allows():
    outcome = await Approval(enabled=False, foreground=True).resolve("mcp://x/y", "c", "s")
    assert outcome.allowed
    assert outcome.authz_decision == "approval_disabled"


@pytest.mark.asyncio
async def test_background_hub_fails_safe_to_deny():
    # No TUI to approve in -> never silently run (ADR-0018).
    outcome = await Approval(enabled=True, foreground=False).resolve("mcp://x/y", "c", "s")
    assert not outcome.allowed
    assert outcome.authz_decision == "prompt_denied"
    assert outcome.reason == "no_approval_channel"


@pytest.mark.asyncio
async def test_session_allow_remembered():
    appr = Approval(enabled=True, foreground=True)
    appr._session_allows.add("mcp://x/y")
    outcome = await appr.resolve("mcp://x/y", "c", "s")
    assert outcome.allowed and outcome.session


@pytest.mark.asyncio
async def test_keypress_allow(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("a\n"))
    outcome = await Approval(enabled=True, foreground=True).resolve("mcp://x/y", "c", "s")
    assert outcome.allowed
    assert outcome.authz_decision == "prompt_allowed"
    assert not outcome.persistent


@pytest.mark.asyncio
async def test_keypress_allow_always_is_persistent(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("A\n"))
    outcome = await Approval(enabled=True, foreground=True).resolve("mcp://x/y", "c", "s")
    assert outcome.allowed and outcome.persistent


@pytest.mark.asyncio
async def test_keypress_deny_always_is_persistent(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("D\n"))
    outcome = await Approval(enabled=True, foreground=True).resolve("mcp://x/y", "c", "s")
    assert not outcome.allowed and outcome.persistent


@pytest.mark.asyncio
async def test_unknown_keypress_defaults_to_deny(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("z\n"))
    outcome = await Approval(enabled=True, foreground=True).resolve("mcp://x/y", "c", "s")
    assert not outcome.allowed


@pytest.mark.asyncio
async def test_session_allow_records_for_next_call(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("s\n"))
    appr = Approval(enabled=True, foreground=True)
    first = await appr.resolve("mcp://x/y", "c", "s")
    assert first.allowed and first.session
    assert "mcp://x/y" in appr._session_allows
