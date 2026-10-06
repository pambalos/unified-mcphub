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


def _act(tool: str) -> Action:
    return Action.build(
        principal=Principal(id="agent:crew-1"),
        tool=tool,
        verb="call",
        resource="*",
        params={"n": 1},
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

    pack = build(
        out=tmp_path / "pack",
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
    return {"pack": pack, "chain_dir": chain_dir}


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
