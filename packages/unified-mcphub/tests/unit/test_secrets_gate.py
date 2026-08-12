"""The startup secrets gate — refs collection, list-then-unlock, prompt/auto."""

from __future__ import annotations

import builtins

import pytest

import unified_mcphub.hub as hub_mod
from unified_mcphub.config import OAuthConfig, ServerSpec, Upstream, load_config
from unified_mcphub.hub import Hub
from unified_mcphub.secrets import SecretsStore


def _http(ref: str | None = None, *, oauth: bool = False, enabled: bool = True) -> ServerSpec:
    return ServerSpec(
        upstream=Upstream(url="https://example.com/mcp"),
        auth_secret_ref=ref,
        oauth=OAuthConfig(issuer="https://example.com") if oauth else None,
        enabled=enabled,
    )


class _NotATty:
    def isatty(self) -> bool:
        return False


def _keyring_store(hub: Hub) -> SecretsStore:
    """Force the hub onto a keyring-backed store so `fake_keyring` works on any OS."""
    store = SecretsStore(backend="keyring")
    hub.secrets = store
    return store


def test_required_refs_collects_secret_and_oauth(hub_home):
    hub = Hub(load_config())
    hub.config.workspace.servers = {
        "hf": _http(ref="hf-token"),
        "linear": _http(oauth=True),
        "fs": ServerSpec(upstream=Upstream(command="python")),  # no secret
        "off": _http(ref="nope", enabled=False),  # disabled → excluded
    }
    assert hub._required_secret_refs() == ["hf-token", "linear-oauth-refresh"]


def test_gate_noop_when_no_store(hub_home, fake_keyring, monkeypatch):
    """No secrets.enc yet → never touch the key backend, never prompt — even in
    prompt mode with no TTY (which would otherwise fail fast)."""
    hub = Hub(load_config())
    _keyring_store(hub)
    hub.config.workspace.servers = {"hf": _http(ref="hf-token")}
    hub.config.hub.secrets.access_mode = "prompt"
    monkeypatch.setattr(hub_mod.sys, "stdin", _NotATty())
    monkeypatch.setattr(hub_mod.sys, "stdout", _NotATty())
    hub._gate_secrets()  # must not raise


def test_prompt_mode_without_tty_fails_fast(hub_home, fake_keyring, monkeypatch):
    hub = Hub(load_config())
    store = _keyring_store(hub)
    store.set("hf-token", "v")  # store now exists → gate engages
    hub.config.workspace.servers = {"hf": _http(ref="hf-token")}
    hub.config.hub.secrets.access_mode = "prompt"
    monkeypatch.setattr(hub_mod.sys, "stdin", _NotATty())
    monkeypatch.setattr(hub_mod.sys, "stdout", _NotATty())
    with pytest.raises(SystemExit, match="needs a TTY"):
        hub._gate_secrets()


def test_auto_mode_unlocks_without_prompt(hub_home, fake_keyring, monkeypatch):
    hub = Hub(load_config())
    store = _keyring_store(hub)
    store.set("hf-token", "v")
    hub.config.workspace.servers = {"hf": _http(ref="hf-token")}
    hub.config.hub.secrets.access_mode = "auto"

    unlocked = {"n": 0}
    monkeypatch.setattr(store, "unlock", lambda: unlocked.__setitem__("n", unlocked["n"] + 1))
    # input() must never be called in auto mode.
    monkeypatch.setattr(builtins, "input", lambda *a: pytest.fail("auto must not prompt"))
    hub._gate_secrets()
    assert unlocked["n"] == 1
