"""The hub's signing key: a signed chain, and a recorded start point.

What signing buys is that a rewritten chain needs the key as well as write
access to the files. What the start point buys is that a hub which ran
unsigned before it was given a key still verifies — and that a hub which
*stops* signing afterwards does not.
"""

from __future__ import annotations

import base64
import json

import pytest

from unified_enforce.attest import b64u, key_id
from unified_enforce.signing import Signer

from unified_mcphub import audit_reader, signing
from unified_mcphub.audit import AuditLog
from unified_mcphub.cli import main
from unified_mcphub.config import audit_dir, load_config
from unified_mcphub.hub import Hub
from unified_mcphub.secrets import SecretsStore


def _seed() -> str:
    return signing.generate_seed()


# --- the key -------------------------------------------------------------------


def test_the_key_id_is_derived_from_the_public_key():
    signer = signing.signer_from_secret(_seed())
    assert signer.key_id == key_id(b64u(signer.public_bytes()))


@pytest.mark.parametrize("bad", ["not base64!", base64.b64encode(b"short").decode()])
def test_a_malformed_seed_is_refused(bad):
    with pytest.raises(ValueError):
        signing.signer_from_secret(bad)


# --- the start point -----------------------------------------------------------


def test_the_start_point_is_recorded_once_per_key(hub_home):
    signer = signing.signer_from_secret(_seed())
    assert signing.note_first_signed(signer, 5)
    assert not signing.note_first_signed(signer, 9), "a restart must not move it forward"
    record = signing.load_record()
    assert record is not None and record.since_seq == 5 and record.key_id == signer.key_id
    path = signing.signing_record_path()
    assert (path.stat().st_mode & 0o777) == 0o600


def test_a_new_key_becomes_current_and_the_old_one_is_kept(hub_home):
    first, second = (signing.signer_from_secret(_seed()) for _ in range(2))
    signing.note_first_signed(first, 1)
    signing.note_first_signed(second, 30)
    data = json.loads(signing.signing_record_path().read_text())
    assert data["key_id"] == second.key_id and data["since_seq"] == 30
    assert [p["key_id"] for p in data["previous"]] == [first.key_id]


def test_audit_log_reports_the_first_signed_entry_once(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    seen: list[int] = []
    try:
        _received(log)  # seq 1, unsigned: the key is not attached yet
        log.set_signer(signing.signer_from_secret(_seed()), on_first_signed=seen.append)
        e2 = _received(log)
        e3 = _received(log)
    finally:
        log.stop()
    assert seen == [2]
    assert "sig" in e2 and "sig" in e3


def test_a_failing_start_point_write_is_retried_not_raised(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    calls: list[int] = []

    def flaky(seq: int) -> None:
        calls.append(seq)
        if len(calls) == 1:
            raise OSError("disk full")

    try:
        log.set_signer(signing.signer_from_secret(_seed()), on_first_signed=flaky)
        _received(log)  # must not raise into the audited call
        _received(log)
        _received(log)
    finally:
        log.stop()
    assert calls == [1, 2]


def _received(log: AuditLog) -> dict:
    return log.write_received(
        request_id="r",
        trace_id="t",
        span_id="s",
        caller_id="c",
        caller_token_id=None,
        mcp_server="fs",
        tool="read_file",
        args={},
        authz_decision="allow",
        authz_rule="mcp://*/*",
        audit_level="standard",
    )


# --- end to end through Hub.start ---------------------------------------------


def _hub(store: SecretsStore) -> Hub:
    config = load_config()
    config.hub.secrets.access_mode = "auto"
    hub = Hub(config)
    hub.secrets = store  # keyring-backed, so fake_keyring works on any OS
    return hub


async def _run_one_call(hub: Hub) -> None:
    await hub.start()
    try:
        body = await hub._handle_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "filesystem__list_files", "arguments": {}},
            },
            "claude-code",
        )
        assert "result" in body, body
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_a_hub_with_a_key_signs_from_its_first_entry(hub_home, fake_keyring, capsys):
    store = SecretsStore(backend="keyring")
    seed = _seed()
    store.set("hub-signing-key", seed)
    signer = signing.signer_from_secret(seed)

    await _run_one_call(_hub(store))

    entries = list(audit_reader.tail(audit_dir()))
    assert entries and all(e.get("key_id") == signer.key_id for e in entries)
    record = signing.load_record()
    assert record is not None and record.since_seq == entries[0]["seq"]

    assert main(["audit", "verify"]) == 0
    out = capsys.readouterr().out
    assert "chain OK" in out and f"signatures by key {signer.key_id}" in out


@pytest.mark.asyncio
async def test_a_hub_that_ran_unsigned_first_still_verifies(hub_home, fake_keyring, capsys):
    store = SecretsStore(backend="keyring")
    store.set("unrelated", "x")  # a store exists, but holds no signing key
    await _run_one_call(_hub(store))
    assert signing.load_record() is None
    assert main(["audit", "verify"]) == 0
    assert "signatures not checked" in capsys.readouterr().out

    store.set("hub-signing-key", _seed())
    await _run_one_call(_hub(store))
    record = signing.load_record()
    assert record is not None and record.since_seq > 1
    assert main(["audit", "verify"]) == 0
    assert f"from seq {record.since_seq}" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_hub_that_stops_signing_fails_verification(hub_home, fake_keyring, capsys):
    """The downgrade an attacker with the account but not the key would want:
    remove the key, and carry on writing a chain that verifies by hash."""
    store = SecretsStore(backend="keyring")
    store.set("hub-signing-key", _seed())
    await _run_one_call(_hub(store))
    store.remove("hub-signing-key")
    await _run_one_call(_hub(store))

    assert audit_reader.verify(audit_dir()).ok, "hash-only, it looks fine"
    assert main(["audit", "verify"]) == 1
    assert "unsigned" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_malformed_key_stops_start_up(hub_home, fake_keyring):
    store = SecretsStore(backend="keyring")
    store.set("hub-signing-key", "not-a-key")
    hub = _hub(store)
    with pytest.raises(SystemExit, match="hub-signing-key"):
        await hub.start()
    hub.audit.stop()


def test_the_seed_round_trips_through_the_signer():
    seed = _seed()
    signer = signing.signer_from_secret(seed)
    assert base64.b64encode(signer.private_bytes()).decode() == seed
    assert isinstance(signer, Signer)


@pytest.mark.asyncio
async def test_start_stop_with_no_calls_then_restart_keeps_the_chain(
    hub_home, fake_keyring, capsys, monkeypatch
):
    """Day 1: one call. Day 2: start and stop with no calls (an empty day
    file). Day 2 again: restart and call. The chain must continue from day 1
    -- not restart at GENESIS/seq 1 below signing.json's start point."""
    from datetime import UTC, datetime

    import unified_mcphub.audit as audit_mod
    from unified_enforce.audit import HashChainWriter

    store = SecretsStore(backend="keyring")
    store.set("hub-signing-key", _seed())
    day = {"now": datetime(2026, 10, 1, 12, tzinfo=UTC)}
    monkeypatch.setattr(audit_mod, "utcnow", lambda: day["now"])

    await _run_one_call(_hub(store))
    day["now"] = datetime(2026, 10, 2, 9, tzinfo=UTC)
    idle = _hub(store)
    await idle.start()
    await idle.stop()
    assert (audit_dir() / "2026-10-02.jsonl").read_bytes() == b""
    await _run_one_call(_hub(store))

    entries = [
        json.loads(line)
        for f in sorted(audit_dir().glob("*.jsonl"))
        for line in f.read_text().splitlines()
        if line.strip()
    ]
    assert [e["seq"] for e in entries] == list(range(1, len(entries) + 1))
    record = signing.load_record()
    assert HashChainWriter.verify(
        audit_dir(), public_key=record.public_bytes(), signed_from_seq=record.since_seq
    ).ok
    assert audit_reader.verify(audit_dir(), record).ok
    assert main(["audit", "verify"]) == 0
    assert "chain OK" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_a_signed_chain_with_its_signing_record_deleted_fails_verify(
    hub_home, fake_keyring, capsys
):
    """Deleting signing.json must not quietly downgrade `audit verify` to a
    hash-only check of a chain that carries signatures."""
    store = SecretsStore(backend="keyring")
    store.set("hub-signing-key", _seed())
    await _run_one_call(_hub(store))
    assert main(["audit", "verify"]) == 0
    capsys.readouterr()

    signing.signing_record_path().unlink()
    assert main(["audit", "verify"]) == 1
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out and "signing.json" in out

    # A hub that never signed still verifies by hash, as before.
    for f in audit_dir().glob("*.jsonl"):
        f.unlink()
    store.remove("hub-signing-key")
    await _run_one_call(_hub(store))
    assert main(["audit", "verify"]) == 0
