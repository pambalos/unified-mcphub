"""Evidence packs, attacked.

The pack exists to be checked by somebody who trusts neither the customer nor
us, so — like test_attest.py — the property under test is not "a good pack
verifies". It is that every way of making a pack say something the signed
record does not is caught, *including after the attacker re-hashes the
manifest*, because the manifest is not a signature and anybody holding the pack
can rewrite it. `test_a_genuine_pack_verifies` guards the rest: a verifier that
always failed would pass every negative case here while proving nothing.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unified_enforce import Action, AuditChain, Enforcer, PolicyEngine, Principal
from unified_enforce.approval import RecordedApproval
from unified_enforce.attest import (
    KEYSET_SCHEMA,
    b64u,
    canonical,
    key_id,
    resolution_payload,
    sign_bytes,
)
from unified_enforce.evidence_pack import ChainSource, build, excerpt, policy_from_yaml
from unified_enforce.pack_verify import verify_pack
from unified_enforce.signing import Signer

FLEET = "acme"
REPORTER = "01REPORTERCREDENTIAL0000"
POLICY = """
version: 1
rules:
  - id: reads
    match: {tool: "mcp://files/read"}
    effect: allow
  - id: payouts-need-a-human
    match: {tool: "mcp://bank/payout"}
    effect: defer
  - id: no-vault
    match: {tool: "mcp://vault/*"}
    effect: deny
"""
APPROVER = {
    "subject": "local:01APPROVER",
    "email": "alice@acme.test",
    "session_id": "sess-1",
    "authenticated_at_ms": 1_786_000_000_000,
}


class Key:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = b64u(self.private.public_key().public_bytes_raw())
        self.kid = key_id(self.public)


def _keyset(root: Key, decision: Key) -> dict:
    payload = json.dumps(
        {
            "schema": KEYSET_SCHEMA,
            "issued_at_ms": 0,
            "expires_at_ms": 2**62,
            "keys": [
                {
                    "kid": decision.kid,
                    "alg": "EdDSA",
                    "role": "decision",
                    "public_key": decision.public,
                    "expires_at_ms": 2**62,
                }
            ],
        }
    ).encode()
    return sign_bytes(payload, root.private, root.kid)


#: A value that must never appear in a digests-only pack.
SECRETISH = "acct-UAI-203-do-not-export"


def _act(tool: str) -> Action:
    return Action.build(
        principal=Principal(id="agent:crew-1"),
        tool=tool,
        verb="call",
        resource="*",
        params={"n": 1, "account": SECRETISH},
    )


@pytest.fixture
def world(tmp_path: Path) -> dict:
    """A signed sidecar chain with policy decisions and one console-approved
    deferral, the control plane's export of it, and the keys to check both."""
    root, decision_key = Key(), Key()
    signer = Signer.generate("sidecar-1")
    engine = PolicyEngine.from_yaml(POLICY)
    chain_dir = tmp_path / "chain"
    chain = AuditChain(chain_dir, signer=signer)
    chain.start()
    enforcer = Enforcer(engine, chain=chain)
    rows = []
    try:
        for tool in ("mcp://files/read", "mcp://vault/get", "mcp://bank/payout"):
            a = _act(tool)
            d = enforcer.enforce(a)
            rows.append({"action": a, "decision": d})
        payout = rows[-1]["action"]
        attestation = {
            "fleet_id": FLEET,
            "key_id": decision_key.kid,
            "nonce": "n-1",
            "resolved_at_ms": 1_786_000_100_000,
            "expires_at_ms": 1_786_000_200_000,
        }
        wire = {
            "sub": APPROVER["subject"],
            "email": APPROVER["email"],
            "sid": APPROVER["session_id"],
            "auth_time_ms": APPROVER["authenticated_at_ms"],
        }
        signed = canonical(
            resolution_payload(
                action_digest=payout.digest(strict=False),
                kind="allow",
                approver=wire,
                scope=None,
                **{
                    k: attestation[k]
                    for k in ("resolved_at_ms", "expires_at_ms", "nonce", "fleet_id")
                },
            )
        )
        attestation["signature"] = b64u(decision_key.private.sign(signed))
        chain.append_approval(
            RecordedApproval(
                action_digest=payout.digest(strict=False),
                verdict="allow",
                source="approval",
                rule_id="payouts-need-a-human",
                kind="allow",
                decided_by=APPROVER["subject"],
                approver=dict(APPROVER),
                attestation=attestation,
                policy_digest=engine.policy_digest,
            )
        )
    finally:
        chain.stop()

    entries = [
        json.loads(line)
        for f in sorted(chain_dir.glob("*.jsonl"))
        for line in f.read_text().splitlines()
    ]
    decisions = {e["payload"]["action_digest"]: e for e in entries if e["kind"] == "decision"}
    csv_path = tmp_path / "export.csv"
    columns = [
        "tool", "verdict", "policy_digest", "attested", "reporter_id", "chain_hash",
        "action_digest", "decision_reported", "decided_by",
    ]  # fmt: skip
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=columns)
        w.writeheader()
        for r in rows:
            digest = r["action"].digest()
            e = decisions[digest]
            w.writerow(
                {
                    "tool": r["action"].tool,
                    "verdict": e["payload"]["verdict"],
                    "policy_digest": engine.policy_digest,
                    "attested": "true",
                    "reporter_id": REPORTER,
                    "chain_hash": e["hash"],
                    "action_digest": digest,
                    "decision_reported": "true",
                    "decided_by": APPROVER["subject"]
                    if r["action"].tool == "mcp://bank/payout"
                    else "",
                }
            )
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(POLICY)
    keyset_file = tmp_path / "keyset.json"
    keyset_file.write_text(json.dumps(_keyset(root, decision_key)))

    build_kwargs = dict(
        title="test",
        fleet_id=FLEET,
        start=datetime(2000, 1, 1, tzinfo=UTC),
        end=datetime.now(UTC) + timedelta(days=1),
        csv_path=csv_path,
        chains=[
            ChainSource(
                name="sidecar",
                directory=chain_dir,
                public_key=base64.b64encode(signer.public_bytes()).decode(),
                reporter_id=REPORTER,
            )
        ],
        policies=[policy_from_yaml(policy_file)],
        root_key=root.public,
        keyset_path=keyset_file,
    )
    pack = build(out=tmp_path / "pack", **build_kwargs)
    return {
        "pack": pack,
        "chain_dir": chain_dir,
        "build": build_kwargs,
        "tmp": tmp_path,
        "signer": signer,
    }


def _failures(pack: Path) -> list[str]:
    report = verify_pack(pack)
    return [f"{c.name}: {c.detail}" for c in report.checks if not c.ok and not c.warning]


def _tamper(pack: Path, rel: str, fn) -> None:
    """Edit a file and then do what an attacker would: re-hash the manifest."""
    path = pack / rel
    path.write_text(fn(path.read_text()))
    manifest = json.loads((pack / "manifest.json").read_text())
    for f in manifest["files"]:
        f["sha256"] = hashlib.sha256((pack / f["path"]).read_bytes()).hexdigest()
    (pack / "manifest.json").write_text(json.dumps(manifest))


def test_a_genuine_pack_verifies(world):
    report = verify_pack(world["pack"])
    assert report.ok, _failures(world["pack"])
    names = {c.name for c in report.checks}
    assert any(n.startswith("approval ") for n in names), "the approval must actually be checked"
    assert any(n.startswith("policy ") for n in names)
    assert any(c.name == "export rows" and "3 of 3" in c.detail for c in report.checks)


def test_the_bundled_verifier_runs_on_its_own(world, tmp_path):
    """`python verify/verify.py` from anywhere, using the pack's own copies —
    the auditor's path, with no `unified_enforce` import involved."""
    moved = tmp_path / "elsewhere" / "pack"
    shutil.copytree(world["pack"], moved)
    result = subprocess.run(
        [sys.executable, "-I", str(moved / "verify" / "verify.py")],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: VERIFIED" in result.stdout


def test_an_added_file_is_noticed(world):
    (world["pack"] / "export" / "extra.csv").write_text("surprise\n")
    assert any("not in manifest" in f for f in _failures(world["pack"]))


def test_editing_an_approval_breaks_both_the_chain_and_the_control_plane_signature(world):
    _tamper(
        world["pack"],
        "chains/sidecar/chain.jsonl",
        lambda s: s.replace('"kind":"allow"', '"kind":"allow_always"'),
    )
    failures = _failures(world["pack"])
    assert any("hash mismatch" in f for f in failures)
    assert any("signature does not verify" in f for f in failures)


def test_swapping_the_approver_is_caught(world):
    _tamper(
        world["pack"],
        "chains/sidecar/chain.jsonl",
        lambda s: s.replace("alice@acme.test", "ceo@acme.test"),
    )
    assert any("signature does not verify" in f for f in _failures(world["pack"]))


def test_an_export_row_that_contradicts_the_chain_is_caught(world):
    _tamper(
        world["pack"],
        "export/evidence.csv",
        lambda s: s.replace("mcp://vault/get,deny", "mcp://vault/get,allow"),
    )
    assert any("verdict 'allow' vs chain 'deny'" in f for f in _failures(world["pack"]))


def test_deleting_an_entry_breaks_the_chain(world):
    def drop_second(s: str) -> str:
        lines = s.splitlines()
        return "\n".join(lines[:1] + lines[2:]) + "\n"

    _tamper(world["pack"], "chains/sidecar/chain.jsonl", drop_second)
    assert any("chain break" in f for f in _failures(world["pack"]))


def test_stripping_signatures_is_caught(world):
    _tamper(world["pack"], "chains/sidecar/chain.jsonl", lambda s: re.sub(r',"sig":"[^"]*"', "", s))
    assert any("signed from the start" in f for f in _failures(world["pack"]))


def test_stripping_signatures_and_the_key_is_caught_by_the_control_planes_attestation(world):
    """The attacker who deletes the key too turns the chain into an honest-
    looking unsigned one. What gives them away is the export: the control plane
    verified those rows against the key the reporter registered."""
    _tamper(world["pack"], "chains/sidecar/chain.jsonl", lambda s: re.sub(r',"sig":"[^"]*"', "", s))
    _tamper(
        world["pack"],
        "chains/sidecar/meta.json",
        lambda s: json.dumps({**json.loads(s), "public_key": None}),
    )
    assert any("attested this row" in f for f in _failures(world["pack"]))


def test_weakening_the_policy_is_caught(world):
    index = json.loads((world["pack"] / "policies" / "index.json").read_text())
    normalized = next(iter(index.values()))["normalized"]
    _tamper(world["pack"], f"policies/{normalized}", lambda s: s.replace('"deny"', '"allow"'))
    assert any("does NOT hash" in f for f in _failures(world["pack"]))


def test_an_excerpt_is_contiguous_and_anchored(world):
    """Starting mid-chain is allowed — retention prunes, windows narrow — but
    the excerpt must carry its anchor and keep every entry between its ends."""
    entries = [
        json.loads(line)
        for f in sorted(world["chain_dir"].glob("*.jsonl"))
        for line in f.read_text().splitlines()
    ]
    second_ts = datetime.fromisoformat(entries[1]["ts"])
    lines, meta = excerpt(
        ChainSource(name="s", directory=world["chain_dir"]),
        second_ts,
        datetime.now(UTC) + timedelta(days=1),
    )
    assert meta["anchor"] == entries[0]["hash"]
    assert meta["first_seq"] == entries[1]["seq"]
    assert len(lines) == len(entries) - 1


# --- payloads: include vs digests-only -------------------------------------------------


def _run_bundled(pack: Path, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(pack / "verify" / "verify.py")],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def test_an_included_pack_checks_every_payload(world):
    assert SECRETISH in (world["pack"] / "chains" / "sidecar" / "chain.jsonl").read_text()
    detail = next(c.detail for c in verify_pack(world["pack"]).checks if c.name == "chain sidecar")
    assert "6 verified against their digests, 0 withheld" in detail  # params + extra, x3
    assert json.loads((world["pack"] / "manifest.json").read_text())["payloads"] == "include"
    assert (world["pack"] / "verify" / "detach.py").is_file()


def test_an_edited_payload_fails_the_pack(world):
    """The entry hash covers the payload's digest, not the payload — so this is
    the edit that a hash check alone would miss."""
    _tamper(
        world["pack"],
        "chains/sidecar/chain.jsonl",
        lambda s: s.replace(SECRETISH, "acct-somebody-else", 1),
    )
    assert any("does not match its digest" in f for f in _failures(world["pack"]))


def test_a_digests_only_pack_withholds_content_and_still_verifies_on_its_own(world):
    pack = build(out=world["tmp"] / "digests", payloads="digests-only", **world["build"])
    for path in pack.rglob("*"):
        if path.is_file() and path.suffix in (".jsonl", ".json", ".md", ".csv"):
            assert SECRETISH not in path.read_text(), f"{path} leaks a withheld value"
    for line in (pack / "chains" / "sidecar" / "chain.jsonl").read_text().splitlines():
        assert "salts" not in json.loads(line), "a salt beside a withheld value aids guessing"

    report = verify_pack(pack)
    assert report.ok, _failures(pack)
    detail = next(c.detail for c in report.checks if c.name == "chain sidecar")
    assert "0 verified against their digests, 6 withheld" in detail
    assert json.loads((pack / "manifest.json").read_text())["payloads"] == "digests-only"
    assert "Payloads withheld" in (pack / "README.md").read_text()

    # The auditor's path: the pack's own verifier, nothing of ours importable.
    moved = world["tmp"] / "elsewhere" / "digests"
    shutil.copytree(pack, moved)
    result = _run_bundled(moved, world["tmp"])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "6 withheld" in result.stdout and "RESULT: VERIFIED" in result.stdout


def test_a_withheld_payload_can_be_produced_and_checked_later(world):
    """The point of the commitment: the customer hands over one value and its
    salt, and the auditor checks it against the signed entry in the pack."""
    from unified_enforce import detach

    pack = build(out=world["tmp"] / "digests", payloads="digests-only", **world["build"])
    withheld = [
        json.loads(line)
        for line in (pack / "chains" / "sidecar" / "chain.jsonl").read_text().splitlines()
    ]
    original = [
        json.loads(line)
        for f in sorted(world["chain_dir"].glob("*.jsonl"))
        for line in f.read_text().splitlines()
    ]
    path = "payload.action.params"
    produced_value = detach.get(original[0], path)[1]
    produced_salt = base64.b64decode(original[0]["salts"][path])
    assert detach.digest(produced_salt, produced_value) == withheld[0]["detached"][path]
    assert (
        detach.digest(produced_salt, {"n": 1, "account": "a guess"})
        != (withheld[0]["detached"][path])
    )


def test_a_salt_left_beside_a_withheld_value_fails(world):
    pack = build(out=world["tmp"] / "digests", payloads="digests-only", **world["build"])

    def leak_a_salt(s: str) -> str:
        lines = s.splitlines()
        first = json.loads(lines[0])
        first["salts"] = {"payload.action.params": base64.b64encode(b"x" * 16).decode()}
        return "\n".join([json.dumps(first), *lines[1:]]) + "\n"

    _tamper(pack, "chains/sidecar/chain.jsonl", leak_a_salt)
    assert any("salt present without its content" in f for f in _failures(pack))


@pytest.mark.parametrize("original,moved,forged", [(123, b"1", 23), (-500, b"-", 500)])
def test_bytes_moved_from_a_value_into_its_salt_fail_the_pack(world, original, moved, forged):
    """The digest has no framing between salt and content, so a detached number
    could be edited by moving its leading bytes into the salt -- `123` as
    salt+"1" and `23` -- and still "match". The pack's verifier (detach.check)
    pins the salt to 16 bytes, which pins the boundary."""
    chain = AuditChain(world["chain_dir"], signer=world["signer"])
    chain.start()
    try:
        chain.append("note", {"n": original}, detach=["payload.n"])
    finally:
        chain.stop()
    pack = build(out=world["tmp"] / f"shifted{original}", **world["build"])
    assert verify_pack(pack).ok, _failures(pack)  # genuine first: the attack is the edit

    def shift(s: str) -> str:
        lines = s.splitlines()
        out = []
        for line in lines:
            e = json.loads(line)
            if e.get("kind") == "note":
                raw = base64.b64decode(e["salts"]["payload.n"])
                e["payload"]["n"] = forged
                e["salts"]["payload.n"] = base64.b64encode(raw + moved).decode()
            out.append(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return "\n".join(out) + "\n"

    _tamper(pack, "chains/sidecar/chain.jsonl", shift)

    assert any("salt is 17 bytes" in f for f in _failures(pack)), _failures(pack)


def test_only_entries_with_inline_content_are_called_legacy(world, tmp_path):
    """A digests-only pack calls an entry "legacy" only when it predates
    detachable payloads *and* carries content inline. The world's approval
    entry has no `detached` because it has nothing to detach -- counting it
    told the auditor that undisclosable content was present in a chain
    written entirely after the format existed."""
    pack = build(out=world["tmp"] / "digests-legacy", payloads="digests-only", **world["build"])
    meta = json.loads((pack / "chains" / "sidecar" / "meta.json").read_text())
    assert meta["legacy_inline_entries"] == 0
    report = verify_pack(pack)
    assert not any("predate detachable payloads" in c.detail for c in report.checks)

    # A genuinely pre-format decision (params inline, no `detached`) still is,
    # and is said so.
    from unified_enforce.audit import HashChainWriter

    legacy_dir = tmp_path / "legacy-chain"
    writer = HashChainWriter(legacy_dir, strict=False)
    writer.start()
    writer.append(
        {
            "kind": "decision",
            "seq": 1,
            "ts": datetime.now(UTC).isoformat(),
            "payload": {"action": {"params": {"account": "inline"}}, "verdict": "allow"},
        }
    )
    writer.append(
        {"kind": "approval", "seq": 2, "ts": datetime.now(UTC).isoformat(), "payload": {}}
    )
    writer.stop()
    kwargs = {**world["build"], "chains": [ChainSource(name="old", directory=legacy_dir)]}
    kwargs["csv_path"] = None
    pack = build(out=tmp_path / "legacy-pack", payloads="digests-only", **kwargs)
    meta = json.loads((pack / "chains" / "old" / "meta.json").read_text())
    assert meta["legacy_inline_entries"] == 1


@pytest.mark.parametrize(
    "stage, name",
    [
        ("check_manifest", "manifest"),
        ("check_chains", "chains"),
        ("check_approvals", "approvals"),
        ("check_policies", "policies"),
        ("check_rows", "export rows"),
    ],
)
def test_a_stage_that_raises_fails_by_name_and_the_rest_still_run(world, monkeypatch, stage, name):
    """The `_stage` backstop: an exception nobody anticipated is that stage
    FAILING, named, beside every other stage's verdict -- never a traceback."""
    from unified_enforce import pack_verify

    def explode(*a, **k):
        raise RuntimeError("doctored beyond recognition")

    monkeypatch.setattr(pack_verify, stage, explode)
    report = verify_pack(world["pack"])  # does not raise
    assert not report.ok
    failed = [c for c in report.checks if c.name == name and not c.ok]
    assert failed and "could not be checked: RuntimeError" in failed[-1].detail
    # Another stage's verdict is still there.
    other = "chain sidecar" if name == "manifest" else "manifest"
    assert any(c.name == other for c in report.checks)
