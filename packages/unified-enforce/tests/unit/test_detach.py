"""Detachable payloads (detach.py): recorded raw, withheld on export, verified either way.

The properties under test are the ones an auditor relies on: a chain written
before this module still verifies; a payload edited after the fact fails even
though the hash no longer covers it directly; a withheld payload breaks
nothing, signatures included; and a withheld payload leaves no salt behind to
help somebody confirm a guess.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path

import pytest

from unified_enforce import (
    Action,
    ActionContext,
    AuditChain,
    HashChainWriter,
    PolicyEngine,
    Principal,
    detach,
)
from unified_enforce.canonical import CanonicalizationError
from unified_enforce.pack_verify import _verify_chain
from unified_enforce.signing import Signer

POLICY = """
version: 1
rules:
  - {id: anything, match: {tool: "*"}, effect: allow, audit_level: minimal}
"""


def _lines(d: Path) -> list[dict]:
    return [
        json.loads(line)
        for p in sorted(d.glob("*.jsonl"))
        for line in p.read_text().splitlines()
        if line.strip()
    ]


def _rewrite(d: Path, fn) -> None:
    for p in sorted(d.glob("*.jsonl")):
        entries = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
        p.write_text("".join(json.dumps(fn(e)) + "\n" for e in entries))


def _decisions(d: Path, *, signer: Signer | None = None, **kw) -> Path:
    engine = PolicyEngine.from_yaml(POLICY)
    chain = AuditChain(d, signer=signer, **kw)
    chain.start()
    try:
        for n in range(3):
            action = Action.build(
                principal=Principal(id="agent:x"),
                tool="mcp://tickets/update",
                verb="call",
                resource="*",
                params={"ticket": f"UAI-20{n}", "body": "please refund"},
                context=ActionContext(extra={"session": "s-1"}),
            )
            chain.append_decision(action, engine.decide(action))
    finally:
        chain.stop()
    return d


# --- the rule ---------------------------------------------------------------------


def test_salted_digests_differ_and_do_not_confirm_a_guess():
    a = detach.detach({"args": "UAI-203"}, ["args"])
    b = detach.detach({"args": "UAI-203"}, ["args"])
    assert a["detached"]["args"] != b["detached"]["args"], "a fresh salt per value"
    unsalted = hashlib.sha256(detach.canonical("UAI-203")).hexdigest()
    assert unsalted not in (a["detached"]["args"], b["detached"]["args"])


def test_detach_does_not_mutate_its_input_and_skips_absent_paths():
    entry = {"payload": {"action": {"params": {"x": 1}}}}
    out = detach.detach(entry, ["payload.action.params", "payload.action.context.extra"])
    assert entry == {"payload": {"action": {"params": {"x": 1}}}}
    assert set(out["detached"]) == {"payload.action.params"}
    gone = detach.detach(entry, ["payload.action.params"], record=False)
    assert entry["payload"]["action"]["params"] == {"x": 1}
    assert "params" not in gone["payload"]["action"]
    assert gone["unrecorded"] == ["payload.action.params"]


def test_an_entry_without_detached_fields_hashes_as_it_always_did():
    entry = {"kind": "decision", "seq": 1, "prev_hash": "0" * 64, "sig": "s", "key_id": "k"}
    assert detach.hashable_body(entry) == {"kind": "decision", "seq": 1, "prev_hash": "0" * 64}
    assert detach.check(entry) == (True, 0, 0, 0, None)


def test_redact_keeps_the_hashed_body_identical():
    entry = detach.detach({"args": {"q": "secret"}, "tool": "t"}, ["args"])
    redacted = detach.redact(entry)
    assert "args" not in redacted and "salts" not in redacted
    assert detach.hashable_body(redacted) == detach.hashable_body(entry)
    assert detach.check(redacted) == (True, 0, 1, 0, None)


# --- chains -----------------------------------------------------------------------


def test_a_chain_written_before_detaching_still_verifies(tmp_path):
    """Built the way the writer built entries before this change — hash over
    the entry minus hash/sig/key_id — and signed. Must verify unchanged, by
    the library and by the pack verifier."""
    signer = Signer.generate("legacy")
    d = tmp_path / "audit"
    d.mkdir()
    prev, lines = "0" * 64, []
    for seq in (1, 2):
        body = {
            "kind": "decision",
            "seq": seq,
            "ts": "2026-01-01T00:00:00+00:00",
            "payload": {"action": {"params": None}, "audit_level": "minimal", "redacted": True},
            "prev_hash": prev,
        }
        h = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        lines.append({**body, "hash": h, "sig": signer.sign_bytes(h.encode()), "key_id": "k"})
        prev = h
    (d / "2026-01-01.jsonl").write_text("".join(json.dumps(e) + "\n" for e in lines))
    result = HashChainWriter.verify(d, public_key=signer.public_bytes())
    assert result.ok and result.entries == 2 and result.payloads_verified == 0
    key = base64.b64encode(signer.public_bytes()).decode()
    assert _verify_chain({"anchor": "0" * 64, "public_key": key}, lines)[0]


def test_detached_entries_verify_with_content_and_after_redaction_signatures_included(tmp_path):
    signer = Signer.generate("sidecar")
    d = _decisions(tmp_path / "audit", signer=signer)
    full = AuditChain.verify(d, public_key=signer.public_bytes())
    assert full.ok and full.payloads_verified == 6 and full.payloads_withheld == 0

    _rewrite(d, detach.redact)
    text = "".join(p.read_text() for p in d.glob("*.jsonl"))
    assert "UAI-20" not in text and "salts" not in text
    redacted = AuditChain.verify(d, public_key=signer.public_bytes())
    assert redacted.ok, redacted.error
    assert redacted.payloads_verified == 0 and redacted.payloads_withheld == 6


def test_edited_content_fails(tmp_path):
    d = _decisions(tmp_path / "audit")
    for p in d.glob("*.jsonl"):
        p.write_text(p.read_text().replace("UAI-201", "UAI-999"))
    result = AuditChain.verify(d)
    assert not result.ok and "does not match its digest (tampered)" in result.error


def test_a_salt_left_without_its_content_fails(tmp_path):
    d = _decisions(tmp_path / "audit")

    def strip_values_keep_salts(e: dict) -> dict:
        out = detach.redact(e)
        out["salts"] = e["salts"]
        return out

    _rewrite(d, strip_values_keep_salts)
    result = AuditChain.verify(d)
    assert not result.ok and "salt present without its content" in result.error


def test_an_edited_digest_fails_the_hash(tmp_path):
    d = _decisions(tmp_path / "audit")

    def swap_digest(e: dict) -> dict:
        e = detach.redact(e)
        e["detached"]["payload.action.params"] = "0" * 64
        return e

    _rewrite(d, swap_digest)
    result = AuditChain.verify(d)
    assert not result.ok and "hash mismatch" in result.error


def test_a_substituted_salt_fails(tmp_path):
    d = _decisions(tmp_path / "audit")

    def new_salt(e: dict) -> dict:
        e["salts"]["payload.action.params"] = base64.b64encode(b"\0" * 16).decode()
        return e

    _rewrite(d, new_salt)
    assert "does not match its digest" in (AuditChain.verify(d).error or "")


def test_a_strict_chain_still_refuses_floats_inside_detached_values(tmp_path):
    """Detaching takes a value out of the hashed bytes; it must not take it out
    of the engine's no-floats rule with it."""
    w = HashChainWriter(tmp_path / "audit", strict=True)
    w.start()
    try:
        with pytest.raises(CanonicalizationError):
            w.append({"payload": {"params": {"amount": 1.5}}}, detach=["payload.params"])
    finally:
        w.stop()


def test_record_payloads_off_stores_no_content_warns_and_verifies(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="unified_enforce.audit"):
        d = _decisions(tmp_path / "audit", record_payloads=False)
    assert any("record_payloads is OFF" in r.getMessage() for r in caplog.records)
    entries = _lines(d)
    assert "UAI-20" not in json.dumps(entries)
    assert all("params" not in e["payload"]["action"] for e in entries)
    assert all(
        e["unrecorded"] == ["payload.action.context.extra", "payload.action.params"]
        for e in entries
    )
    result = AuditChain.verify(d)
    assert result.ok and result.payloads_unrecorded == 6 and result.payloads_withheld == 0

    # The locally kept salt lets a copy held elsewhere be proved later...
    e = entries[0]
    salt = base64.b64decode(e["salts"]["payload.action.params"])
    claimed = {"ticket": "UAI-200", "body": "please refund"}
    assert detach.digest(salt, claimed) == e["detached"]["payload.action.params"]
    # ...and an export strips it like any other.
    assert "salts" not in detach.redact(e)


def test_payload_digest_matches_detach():
    """attest restates detach's digest rule so it can stand alone in the
    control plane and in evidence packs; the two must produce the same bytes."""
    import base64

    from unified_enforce import attest, detach

    entry = detach.detach(
        {"args": {"id": "UAI-203", "n": 1.5, "nested": {"é": [1, None]}}}, ["args"]
    )
    salt, digest = entry["salts"]["args"], entry["detached"]["args"]
    assert attest.payload_content_digest(salt, entry["args"]) == digest
    assert base64.b64decode(salt)
