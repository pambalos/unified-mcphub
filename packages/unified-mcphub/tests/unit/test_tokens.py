"""Unit tests for per-caller bearer tokens — spec §3.2, §3.3 (SEC-MCP-2)."""

from __future__ import annotations

import os
import stat

from unified_mcphub.tokens import TokenStore


def test_mint_writes_0600_and_resolves(tmp_path):
    store = TokenStore(tmp_path)
    token = store.mint("claude-code")
    path = tmp_path / "claude-code.token"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert store.resolve(token) == "claude-code"


def test_resolve_unknown_returns_none(tmp_path):
    store = TokenStore(tmp_path)
    store.mint("claude-code")
    assert store.resolve("not-a-real-token") is None


def test_rotation_invalidates_old(tmp_path):
    store = TokenStore(tmp_path)
    old = store.mint("claude-code")
    new = store.mint("claude-code")  # rotate
    assert old != new
    assert store.resolve(old) is None
    assert store.resolve(new) == "claude-code"


def test_caller_token_id_is_stable_8_hex():
    tid = TokenStore.caller_token_id("abc123")
    assert tid == TokenStore.caller_token_id("abc123")
    assert len(tid) == 8
    assert all(c in "0123456789abcdef" for c in tid)


def test_loose_mode_file_ignored(tmp_path):
    store = TokenStore(tmp_path)
    token = store.mint("claude-code")
    os.chmod(tmp_path / "claude-code.token", 0o644)  # world-readable -> refused
    assert store.resolve(token) is None


def test_list_and_revoke(tmp_path):
    store = TokenStore(tmp_path)
    store.mint("claude-code")
    store.mint("opencode")
    assert store.list_callers() == ["claude-code", "opencode"]
    store.revoke("opencode")
    assert store.list_callers() == ["claude-code"]
