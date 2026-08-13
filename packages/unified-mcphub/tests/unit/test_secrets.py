"""Unit tests for the encrypted secrets store — spec §9."""

from __future__ import annotations

import re
import stat

import pytest

import unified_mcphub.secrets as secrets_mod
from unified_mcphub.config import SecretsConfig
from unified_mcphub.secrets import ENV_KEY_VAR, SecretsStore, resolve_backend

# `fake_keyring` fixture is provided by conftest.py.


def test_set_get_roundtrip(tmp_path, fake_keyring):
    store = SecretsStore(tmp_path / "secrets.enc")
    store.set("github-oauth", "ghp_secretvalue")
    assert store.get("github-oauth") == "ghp_secretvalue"


def test_list_returns_names_not_values(tmp_path, fake_keyring):
    store = SecretsStore(tmp_path / "secrets.enc")
    store.set("a", "v1")
    store.set("b", "v2")
    assert store.list() == ["a", "b"]


def test_remove_and_missing(tmp_path, fake_keyring):
    store = SecretsStore(tmp_path / "secrets.enc")
    store.set("a", "v1")
    store.remove("a")
    assert store.get("a") is None
    assert store.get("never-set") is None


def test_persistence_across_instances(tmp_path, fake_keyring):
    path = tmp_path / "secrets.enc"
    SecretsStore(path).set("k", "v")
    assert SecretsStore(path).get("k") == "v"  # same key from keyring, same file


def test_file_is_0600_and_encrypted(tmp_path, fake_keyring):
    path = tmp_path / "secrets.enc"
    store = SecretsStore(path)
    store.set("token", "PLAINTEXT_SECRET")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert b"PLAINTEXT_SECRET" not in path.read_bytes()


# --- memoization: the backend is read once per process ------------------------


def test_key_is_read_once_per_process(tmp_path, monkeypatch):
    """Many get()s across instances must hit the keychain at most once — this is
    what stops the per-server macOS prompt storm."""
    secrets_mod._reset_key_cache()
    backing: dict = {}
    reads = {"n": 0}

    def counting_get(service, user):
        reads["n"] += 1
        return backing.get((service, user))

    monkeypatch.setattr(secrets_mod.keyring, "get_password", counting_get)
    monkeypatch.setattr(
        secrets_mod.keyring, "set_password", lambda s, u, v: backing.__setitem__((s, u), v)
    )

    path = tmp_path / "secrets.enc"
    SecretsStore(path).set("a", "1")  # creates + caches the key
    reads_after_set = reads["n"]
    # Fresh instances, repeated reads — all served from the module cache.
    for _ in range(5):
        assert SecretsStore(path).get("a") == "1"
    assert reads["n"] == reads_after_set
    secrets_mod._reset_key_cache()


# --- file backend -------------------------------------------------------------


def test_file_backend_roundtrip_no_keyring(tmp_path, monkeypatch):
    """The file backend never calls the keychain and writes a 0600 key file."""
    secrets_mod._reset_key_cache()

    def boom(*a, **k):  # any keychain touch is a bug for this backend
        raise AssertionError("file backend must not touch the keychain")

    monkeypatch.setattr(secrets_mod.keyring, "get_password", boom)
    monkeypatch.setattr(secrets_mod.keyring, "set_password", boom)

    key_file = tmp_path / "secrets.key"
    store = SecretsStore(tmp_path / "secrets.enc", backend="file", key_file=str(key_file))
    store.set("k", "v")
    assert store.get("k") == "v"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    secrets_mod._reset_key_cache()


# --- env backend --------------------------------------------------------------


def test_env_backend_reads_key_from_environment(tmp_path, monkeypatch):
    secrets_mod._reset_key_cache()
    from cryptography.fernet import Fernet

    key = Fernet.generate_key().decode()
    monkeypatch.setenv(ENV_KEY_VAR, key)

    a = SecretsStore(tmp_path / "secrets.enc", backend="env")
    a.set("k", "v")
    # A second store with the same env key decrypts the same blob.
    b = SecretsStore(tmp_path / "secrets.enc", backend="env")
    assert b.get("k") == "v"
    secrets_mod._reset_key_cache()


# --- auto resolution ----------------------------------------------------------


def test_resolve_backend_explicit_passthrough():
    assert resolve_backend(SecretsConfig(key_backend="file")) == "file"


def test_resolve_backend_auto_prefers_env(monkeypatch):
    monkeypatch.setenv(ENV_KEY_VAR, "x")
    assert resolve_backend(SecretsConfig(key_backend="auto")) == "env"


def test_resolve_backend_auto_macos_uses_keyring(monkeypatch):
    monkeypatch.delenv(ENV_KEY_VAR, raising=False)
    monkeypatch.setattr(secrets_mod.sys, "platform", "darwin")
    assert resolve_backend(SecretsConfig(key_backend="auto")) == "keyring"


def test_resolve_backend_auto_headless_linux_falls_back_to_file(monkeypatch):
    monkeypatch.delenv(ENV_KEY_VAR, raising=False)
    monkeypatch.setattr(secrets_mod.sys, "platform", "linux")
    monkeypatch.setattr(secrets_mod, "_keyring_available", lambda: False)
    assert resolve_backend(SecretsConfig(key_backend="auto")) == "file"


# --- the env backend cannot invent a key ------------------------------------------


def test_the_env_backend_refuses_to_generate_a_key_it_cannot_keep(tmp_path, monkeypatch):
    """Silent data loss, caught in review of the branch that introduced it.

    This backend cannot persist anything — the hub cannot export a variable into
    its parent shell. Generating a key anyway encrypts `secrets.enc` with
    something that vanishes when the process exits: the next run generates a
    different key and every stored credential is unrecoverable. The first run
    looks completely fine, which is what makes it worth refusing loudly rather
    than warning.
    """
    monkeypatch.delenv(secrets_mod.ENV_KEY_VAR, raising=False)
    secrets_mod._reset_key_cache()
    store = secrets_mod.SecretsStore(tmp_path / "secrets.enc", backend="env")

    with pytest.raises(secrets_mod.SecretsKeyError, match="cannot store a master key"):
        store.set("github_token", "ghp_credential")

    assert not (tmp_path / "secrets.enc").exists(), (
        "a store was written that nothing will ever be able to decrypt"
    )


def test_the_env_backend_never_logs_the_master_key(tmp_path, monkeypatch, caplog):
    """The value that decrypts every credential must not reach a log stream.

    The earlier version logged it so an operator could copy it, which puts it
    in files, journald and CI output. This codebase already argues the point
    for join tokens: printed once to a terminal, never into a log.
    """
    import logging

    monkeypatch.delenv(secrets_mod.ENV_KEY_VAR, raising=False)
    secrets_mod._reset_key_cache()
    store = secrets_mod.SecretsStore(tmp_path / "secrets.enc", backend="env")

    with caplog.at_level(logging.DEBUG), pytest.raises(secrets_mod.SecretsKeyError):
        store.set("github_token", "ghp_credential")

    # A Fernet key is 44 base64 characters ending in '='. Nothing shaped like
    # one should appear anywhere in the log.
    assert not re.search(r"[A-Za-z0-9_\-]{43}=", caplog.text), caplog.text


def test_a_key_supplied_in_the_environment_round_trips(tmp_path, monkeypatch):
    """The case the backend exists for, pinned so the refusal above cannot
    quietly become "the env backend does not work"."""
    from cryptography.fernet import Fernet

    monkeypatch.setenv(secrets_mod.ENV_KEY_VAR, Fernet.generate_key().decode())
    secrets_mod._reset_key_cache()

    secrets_mod.SecretsStore(tmp_path / "secrets.enc", backend="env").set("t", "value")
    secrets_mod._reset_key_cache()

    assert secrets_mod.SecretsStore(tmp_path / "secrets.enc", backend="env").get("t") == "value"
