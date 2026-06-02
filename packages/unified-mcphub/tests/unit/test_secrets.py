"""Unit tests for the encrypted secrets store — spec §9."""

from __future__ import annotations

import stat

from unified_mcphub.secrets import SecretsStore

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
