"""`implements:` — a rule names the company-policy clauses it carries out.

policy-records.v1 (control plane `specs/policy-records.v1.md`). The properties
that matter, in order:

1. **Backward compatible, provably.** A policy that does not use the key has
   the digest it had before the key existed (pinned below against a value
   computed by the engine *before* this change), writes the chain entry it
   wrote before, and ships the evidence record it shipped before.
2. **Carried end to end.** The clause travels from the rule into the
   decision, the signed chain entry, a human resolution of a DEFER, and the
   record shipped to the control plane.
3. **Checkable offline.** An evidence pack counts decisions per clause and
   per ISO/IEC 42001 control, and the bundled verifier recomputes both from
   the signed chain — so a forged count, or a decision naming a clause its
   rule never claimed, fails the pack.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from unified_enforce import Action, AuditChain, Enforcer, PolicyEngine, Principal
from unified_enforce.action import ActionContext
from unified_enforce.approval import ApprovalRequest, _resolved
from unified_enforce.evidence import summarise
from unified_enforce.evidence_pack import ChainSource, build, policy_from_yaml
from unified_enforce.pack_verify import CLAUSE_DECISIONS, verify_pack
from unified_enforce.policy import Decision, PolicyError, Verdict
from unified_enforce.signing import Signer

#: Every tier, no `implements` anywhere. Its digest below was computed by the
#: engine at the commit before `implements` existed; if this test fails, every
#: audit entry ever written cites a digest that no longer names its policy.
LEGACY = """version: 1
constitutional:
  - id: c1
    match: {tool: "mcp://fs/write_file"}
    effect: deny
attestation_floors:
  - id: af1
    match: {verb: "pay"}
    minimum: derived
rules:
  - id: r1
    match: {tool: "sdk://claims/approve", args: {amount: {matches: ["^[0-9]+$"]}}}
    when: "double(params.amount) > 100.0"
    effect: defer
    reason: big claims need a person
  - id: r2
    match: {tool: "sdk://claims/*"}
    effect: allow
floors:
  - id: f1
    match: {tool: "sdk://claims/pay*"}
counters:
  - id: spend
    match: {tool: "sdk://claims/pay"}
"""
LEGACY_DIGEST = "e43ef3f586710bf8cc8e15ab0ce3f7e8a4bed71320a05df8a640db0cd8f07e13"

LINKED = """version: 1
constitutional:
  - id: no-policy-writes
    match: {tool: "mcp://fs/write_file"}
    effect: deny
    implements: ["ai-policy#3"]
attestation_floors:
  - id: payers-are-proven
    match: {verb: "pay"}
    minimum: attested
    implements: ["human-oversight#2"]
rules:
  - id: big-claims-need-a-person
    match: {tool: "sdk://claims/approve"}
    when: "double(params.amount) > 5000.0"
    effect: defer
    implements: ["claims-authority#4", "human-oversight#2"]
  - id: broken-condition
    match: {tool: "sdk://claims/broken"}
    when: "params.missing.deeper > 1"
    effect: allow
    implements: ["claims-authority#5"]
  - id: claims-reads
    match: {tool: "sdk://claims/get_*"}
    effect: allow
  - id: small-claims
    match: {tool: "sdk://claims/approve"}
    effect: allow
    implements: ["claims-authority#4.1"]
floors:
  - id: payouts-floor
    match: {tool: "sdk://claims/pay*"}
    implements: ["human-oversight#2"]
"""


def _act(tool: str, verb: str = "call", grade: str = "assigned", **params) -> Action:
    return Action.build(
        principal=Principal(id="agent:claims-1", attestation=grade),  # type: ignore[arg-type]
        tool=tool,
        verb=verb,
        resource="*",
        params=params,
        context=ActionContext(origin="sdk"),
    )


# --- 1. backward compatibility ------------------------------------------------------


def test_a_policy_without_the_key_keeps_its_digest():
    assert PolicyEngine.from_yaml(LEGACY).policy_digest == LEGACY_DIGEST


def test_an_empty_list_is_the_same_policy_as_no_key():
    with_empty = LEGACY.replace("    effect: allow\n", "    effect: allow\n    implements: []\n")
    assert "implements: []" in with_empty
    assert PolicyEngine.from_yaml(with_empty).policy_digest == LEGACY_DIGEST


def test_the_key_changes_the_digest_when_used():
    used = LEGACY.replace(
        "    effect: allow\n", '    effect: allow\n    implements: ["claims-authority#4"]\n'
    )
    assert PolicyEngine.from_yaml(used).policy_digest != LEGACY_DIGEST


def test_decisions_from_a_legacy_policy_record_and_ship_exactly_what_they_did(tmp_path):
    engine = PolicyEngine.from_yaml(LEGACY)
    chain = AuditChain(tmp_path / "chain", signer=Signer.generate("s"))
    chain.start()
    try:
        enforcer = Enforcer(engine, chain=chain)
        action = _act("sdk://claims/get_one")
        decision = enforcer.enforce(action)
    finally:
        chain.stop()
    assert decision.implements == ()
    entry = json.loads(next((tmp_path / "chain").glob("*.jsonl")).read_text().splitlines()[-1])
    assert "implements" not in entry["payload"]
    assert "implements" not in summarise(action, decision)


# --- 2. where it is accepted, and what it refuses -------------------------------------


def test_every_deciding_tier_carries_it_and_counters_refuse_it():
    engine = PolicyEngine.from_yaml(LINKED)
    assert engine.policy_digest  # it loads
    with pytest.raises(PolicyError, match="implements"):
        PolicyEngine.from_yaml(
            'version: 1\ncounters:\n  - id: c\n    implements: ["ai-policy#1"]\n'
        )


@pytest.mark.parametrize(
    "refs",
    [
        '["Claims-Authority#4"]',  # upper case key
        '["claims authority#4"]',  # space
        '["claims-authority"]',  # no clause
        '["claims-authority#"]',
        '["#4"]',
        '["claims-authority#§4"]',  # the section sign is display, not identity
        '["claims-authority#4", "claims-authority#4"]',
        "[" + ", ".join(f'"p#{n}"' for n in range(17)) + "]",
        '"claims-authority#4"',  # a string, not a list
    ],
)
def test_a_malformed_reference_is_a_load_error(refs):
    doc = f"version: 1\nrules:\n  - id: r\n    effect: allow\n    implements: {refs}\n"
    with pytest.raises(PolicyError):
        PolicyEngine.from_yaml(doc)


def test_a_dotted_clause_number_is_a_reference():
    doc = 'version: 1\nrules:\n  - id: r\n    effect: allow\n    implements: ["ai-policy#2.1.3"]\n'
    PolicyEngine.from_yaml(doc)


# --- 3. carried into the decision --------------------------------------------------------


@pytest.fixture
def linked() -> PolicyEngine:
    return PolicyEngine.from_yaml(LINKED)


def test_a_rule_decision_names_its_clauses(linked):
    d = linked.decide(_act("sdk://claims/approve", amount=9000))
    assert (d.verdict, d.rule_id) == (Verdict.DEFER, "big-claims-need-a-person")
    assert d.implements == ("claims-authority#4", "human-oversight#2")
    d = linked.decide(_act("sdk://claims/approve", amount=10))
    assert (d.rule_id, d.implements) == ("small-claims", ("claims-authority#4.1",))


def test_floors_constitutional_and_attestation_floors_name_theirs(linked):
    assert linked.decide(_act("mcp://fs/write_file")).implements == ("ai-policy#3",)
    floor = linked.decide(_act("sdk://claims/payout"))
    assert (floor.source, floor.implements) == ("floor", ("human-oversight#2",))
    grade = linked.decide(_act("sdk://claims/get_x", verb="pay"))
    assert grade.source == "attestation_floor"
    assert grade.implements == ("human-oversight#2",)


def test_a_condition_error_still_names_the_rule_it_came_from(linked):
    d = linked.decide(_act("sdk://claims/broken"))
    assert (d.verdict, d.source) == (Verdict.DENY, "condition_error")
    assert d.implements == ("claims-authority#5",)


def test_a_rule_without_the_key_and_the_default_deny_name_nothing(linked):
    assert linked.decide(_act("sdk://claims/get_one")).implements == ()
    d = linked.decide(_act("sdk://elsewhere/x"))
    assert (d.source, d.implements) == ("default", ())


def test_a_human_resolution_keeps_the_clauses_of_the_rule_that_asked(linked):
    action = _act("sdk://claims/approve", amount=9000)
    deferral = linked.decide(action)
    resolved = _resolved(Verdict.ALLOW, "approval", ApprovalRequest(action, deferral))
    assert resolved.implements == deferral.implements


def test_the_chain_entry_and_the_shipped_record_carry_it(tmp_path, linked):
    chain = AuditChain(tmp_path / "chain", signer=Signer.generate("s"))
    chain.start()
    try:
        action = _act("sdk://claims/approve", amount=9000)
        decision = Enforcer(linked, chain=chain).enforce(action)
    finally:
        chain.stop()
    entry = json.loads(next((tmp_path / "chain").glob("*.jsonl")).read_text().splitlines()[-1])
    assert entry["payload"]["implements"] == ["claims-authority#4", "human-oversight#2"]
    # Inside the hashed body, not detached: it is policy metadata.
    assert "payload.implements" not in entry.get("detached", {})
    assert AuditChain.verify(tmp_path / "chain").ok
    record = summarise(action, decision)
    assert record["implements"] == ["claims-authority#4", "human-oversight#2"]


# --- 4. evidence packs -----------------------------------------------------------------

CATALOGUE = {
    "format": "policy-records.v1",
    "standard": "ISO/IEC 42001:2023",
    "controls": [
        {"ref": "A.9.3", "topic": "objectives for responsible use"},
        {"ref": "A.9.4", "topic": "use as intended"},
        {"ref": "A.6.2.8", "topic": "event logs"},
    ],
    "documents": [
        {
            "key": "claims-authority",
            "title": "Claims Authority Policy",
            "version": 3,
            "status": "approved",
            "clauses": [
                {"ref": "claims-authority#4", "number": "4", "controls": ["A.9.3", "A.9.4"]},
                {"ref": "claims-authority#4.1", "number": "4.1", "controls": ["A.9.4"]},
            ],
        },
        {
            "key": "human-oversight",
            "title": "Human Oversight of AI Decisions",
            "version": 1,
            "status": "in_review",
            "clauses": [{"ref": "human-oversight#2", "number": "2", "controls": ["A.9.3"]}],
        },
    ],
}


@pytest.fixture
def pack_world(tmp_path: Path, linked: PolicyEngine) -> dict:
    signer = Signer.generate("sidecar-1")
    chain_dir = tmp_path / "chain"
    chain = AuditChain(chain_dir, signer=signer)
    chain.start()
    try:
        enforcer = Enforcer(linked, chain=chain)
        enforcer.enforce(_act("sdk://claims/approve", amount=9000))  # #4 + oversight#2
        enforcer.enforce(_act("sdk://claims/approve", amount=10))  # #4.1
        enforcer.enforce(_act("sdk://claims/approve", amount=20))  # #4.1
        enforcer.enforce(_act("sdk://claims/get_one"))  # no clause
        enforcer.enforce(_act("sdk://other/thing"))  # default deny
    finally:
        chain.stop()
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(LINKED)
    records = tmp_path / "policy-records.json"
    records.write_text(json.dumps(CATALOGUE))
    kwargs = dict(
        title="clauses",
        fleet_id="acme",
        start=datetime(2000, 1, 1, tzinfo=UTC),
        end=datetime.now(UTC) + timedelta(days=1),
        csv_path=None,
        chains=[
            ChainSource(
                name="sidecar",
                directory=chain_dir,
                public_key=base64.b64encode(signer.public_bytes()).decode(),
            )
        ],
        policies=[policy_from_yaml(policy_file)],
        root_key=None,
        keyset_path=None,
    )
    return {
        "pack": build(out=tmp_path / "pack", policy_records=records, **kwargs),
        "kwargs": kwargs,
        "chain_dir": chain_dir,
        "signer": signer,
        "tmp": tmp_path,
        "linked": linked,
    }


def _failures(pack: Path) -> list[str]:
    return [f"{c.name}: {c.detail}" for c in verify_pack(pack).checks if not c.ok]


def _rehash(pack: Path) -> None:
    manifest = json.loads((pack / "manifest.json").read_text())
    for f in manifest["files"]:
        f["sha256"] = hashlib.sha256((pack / f["path"]).read_bytes()).hexdigest()
    (pack / "manifest.json").write_text(json.dumps(manifest))


def test_a_pack_counts_decisions_per_clause_and_verifies(pack_world):
    pack = pack_world["pack"]
    report = verify_pack(pack)
    assert report.ok, _failures(pack)
    tally = json.loads((pack / CLAUSE_DECISIONS).read_text())
    assert tally["decisions"] == 5
    assert tally["decisions_naming_a_clause"] == 3
    assert tally["clauses"]["claims-authority#4.1"] == {
        "decisions": 2,
        "verdicts": {"allow": 2},
        "rules": ["small-claims"],
        "chains": ["sidecar"],
    }
    assert tally["clauses"]["claims-authority#4"]["verdicts"] == {"defer": 1}
    names = {c.name: c for c in report.checks}
    assert names["policy records: rule links"].ok
    # Every decision by a rule in the cited policy, with or without clauses.
    assert "4 decision(s)" in names["policy records: rule links"].detail
    # The clause in a document still in review is said, not hidden.
    assert "human-oversight#2" in names["policy records: clause status"].detail


def test_the_control_map_rolls_decisions_up_to_42001_controls(pack_world):
    control_map = json.loads((pack_world["pack"] / "control-map.json").read_text())
    rolled = {c["ref"]: c for c in control_map["policy_records"]["controls"]}
    # A.9.3: the one decision that named both #4 and oversight#2 counts once.
    assert rolled["A.9.3"] == {
        "ref": "A.9.3",
        "topic": "objectives for responsible use",
        "clauses": ["claims-authority#4", "human-oversight#2"],
        "decisions": 1,
    }
    assert rolled["A.9.4"]["decisions"] == 3
    # A control no clause addresses is a gap, shown as one.
    assert rolled["A.6.2.8"] == {
        "ref": "A.6.2.8",
        "topic": "event logs",
        "clauses": [],
        "decisions": 0,
    }
    assert any(c["ref"] == "5.2 / A.2.2, A.2.3" for c in control_map["controls"])
    readme = (pack_world["pack"] / "README.md").read_text()
    assert "Company policies behind these decisions" in readme
    assert "`claims-authority#4.1`" in readme


def test_a_forged_clause_count_fails_even_after_rehashing_the_manifest(pack_world):
    pack = pack_world["pack"]
    path = pack / CLAUSE_DECISIONS
    tally = json.loads(path.read_text())
    tally["clauses"]["claims-authority#4.1"]["decisions"] = 200
    path.write_text(json.dumps(tally))
    _rehash(pack)
    assert any("decisions per clause" in f for f in _failures(pack))


def test_a_forged_control_rollup_fails(pack_world):
    pack = pack_world["pack"]
    path = pack / "control-map.json"
    control_map = json.loads(path.read_text())
    for c in control_map["policy_records"]["controls"]:
        if c["ref"] == "A.6.2.8":
            c["clauses"], c["decisions"] = ["claims-authority#4"], 7
    path.write_text(json.dumps(control_map))
    _rehash(pack)
    assert any("policy records: controls" in f for f in _failures(pack))


def test_a_decision_naming_a_clause_its_rule_never_claimed_fails(pack_world, tmp_path):
    """The link lives in the hashed policy document. A chain entry claiming a
    different clause for the same rule and digest contradicts it -- caught
    even though the entry itself is genuinely signed."""
    linked = pack_world["linked"]
    chain = AuditChain(pack_world["chain_dir"], signer=pack_world["signer"])
    chain.start()
    try:
        action = _act("sdk://claims/get_two")
        forged = Decision(
            Verdict.ALLOW,
            "claims-reads",
            "wildcard",
            policy_digest=linked.policy_digest,
            implements=("claims-authority#4",),
        )
        Enforcer(linked, chain=chain).record(action, forged)
    finally:
        chain.stop()
    pack = build(out=tmp_path / "pack2", **pack_world["kwargs"])
    failures = _failures(pack)
    assert any("rule links" in f and "claims-reads" in f for f in failures), failures


def test_without_a_catalogue_the_pack_still_counts_clauses_and_says_what_is_missing(pack_world):
    pack = build(out=pack_world["tmp"] / "bare", **pack_world["kwargs"])
    report = verify_pack(pack)
    assert report.ok, _failures(pack)
    assert not (pack / "policy-records" / "catalogue.json").exists()
    notes = [c for c in report.checks if c.warning and c.name == "policy records: catalogue"]
    assert notes and "not included" in notes[0].detail
    assert "policy_records" not in json.loads((pack / "control-map.json").read_text())


def test_a_catalogue_that_is_not_a_policy_records_export_is_refused(pack_world):
    wrong = pack_world["tmp"] / "wrong.json"
    wrong.write_text(json.dumps({"format": "something-else"}))
    with pytest.raises(ValueError, match="policy-records.v1"):
        build(out=pack_world["tmp"] / "x", policy_records=wrong, **pack_world["kwargs"])


def test_the_bundled_verifier_checks_policy_records_on_its_own(pack_world, tmp_path):
    moved = tmp_path / "elsewhere" / "pack"
    shutil.copytree(pack_world["pack"], moved)
    result = subprocess.run(
        [sys.executable, "-I", str(moved / "verify" / "verify.py")],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[PASS] policy records: decisions per clause" in result.stdout
    assert "[PASS] policy records: controls" in result.stdout


def test_a_pack_built_before_policy_records_still_verifies(pack_world):
    """An older pack has no `policy-records/`; the verifier must not fail it."""
    pack = pack_world["pack"]
    shutil.rmtree(pack / "policy-records")
    control_map = json.loads((pack / "control-map.json").read_text())
    control_map.pop("policy_records")
    (pack / "control-map.json").write_text(json.dumps(control_map))
    manifest = json.loads((pack / "manifest.json").read_text())
    manifest["files"] = [f for f in manifest["files"] if not f["path"].startswith("policy-records")]
    (pack / "manifest.json").write_text(json.dumps(manifest))
    _rehash(pack)
    report = verify_pack(pack)
    assert report.ok, _failures(pack)
    assert any(c.warning and "older builder" in c.detail for c in report.checks)
