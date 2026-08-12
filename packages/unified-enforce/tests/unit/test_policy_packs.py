"""The shipped policy packs, run against an adversarial corpus.

A policy pack is a security claim: "adopt this and these attacks stop." That is
only worth shipping if something checks it, because the failure mode is silent
— a rule that matches nothing looks exactly like a rule that works. Writing
this pack produced two such rules within an hour (see below), which is the
argument for the corpus in one sentence.

Each case in `tests/corpus/` names the action an attacker would attempt, the
verdict required, and why. Attacks are paired with the legitimate calls they
most resemble: a pack that denied everything would pass every attack case and
be useless in production, so the allows are load-bearing too.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from unified_enforce import Action, PolicyEngine, PolicyError, Principal

PACKS = Path(__file__).resolve().parents[2] / "src" / "unified_enforce" / "policies"
CORPUS = Path(__file__).resolve().parents[1] / "corpus"


def _cases(name: str) -> list[dict]:
    return yaml.safe_load((CORPUS / f"{name}.yaml").read_text())["cases"]


def _engine(name: str) -> PolicyEngine:
    return PolicyEngine.from_file(PACKS / f"{name}.yaml")


OWASP = "owasp-llm-top10"


@pytest.mark.parametrize("case", _cases(OWASP), ids=lambda c: c["id"])
def test_owasp_pack_decides_each_case_as_documented(case):
    spec = case["action"]
    action = Action.build(
        principal=Principal(id="agent:crew-1"),
        tool=spec["tool"],
        verb=spec.get("verb", "call"),
        resource=spec.get("resource", "*"),
        params=spec.get("params") or {},
    )
    decision = _engine(OWASP).decide(action)
    assert decision.verdict.value == case["expect"], (
        f"{case['id']} ({case['category']}, {case['intent']}): "
        f"expected {case['expect']}, got {decision.verdict.value} "
        f"via rule={decision.rule_id} source={decision.source}\n"
        f"why this case exists: {case.get('why', '').strip()}"
    )


def test_the_corpus_covers_both_attacks_and_legitimate_traffic():
    """A pack that denies everything passes every attack test and ships a
    product nobody can use. The legitimate cases are what stop that."""
    intents = {c["intent"] for c in _cases(OWASP)}
    assert {"attack", "legitimate"} <= intents
    legitimate = [c for c in _cases(OWASP) if c["intent"] == "legitimate"]
    assert all(c["expect"] == "allow" for c in legitimate)
    assert len(legitimate) >= 3, "too few legitimate cases to catch an over-broad pack"


def test_known_gaps_are_declared_in_the_corpus_not_only_in_prose():
    """`many-small-refunds-each-pass` expects `allow`, deliberately.

    The engine is stateless and cannot count, so a cumulative budget is not
    enforceable today. Encoding that as a passing test with `known_gap: true`
    keeps it visible in test output, and means the day budgets land this test
    fails and someone has to change it on purpose.
    """
    gaps = [c for c in _cases(OWASP) if c.get("known_gap")]
    assert gaps, "no declared gaps — either the pack is perfect or the corpus is flattering it"
    for gap in gaps:
        assert gap["intent"] == "attack"
        assert gap["expect"] == "allow", "a declared gap is an attack that currently succeeds"


# --- properties of the pack itself ---


def test_every_pack_loads():
    """Cheap, and it is how a pack with a malformed rule gets caught before a
    deployment adopts it."""
    packs = sorted(PACKS.glob("*.yaml"))
    assert packs, "no policy packs found"
    for pack in packs:
        PolicyEngine.from_file(pack)


def test_every_rule_explains_itself():
    """`reason` is what an operator reads in the audit log when a call is
    blocked at 3am. A rule without one is a rule nobody can act on."""
    for pack in sorted(PACKS.glob("*.yaml")):
        doc = yaml.safe_load(pack.read_text())
        for section in ("rules", "floors"):
            for entry in doc.get(section) or []:
                assert entry.get("reason"), f"{pack.name}: {entry['id']} has no reason"


def test_brace_globs_are_rejected_at_load():
    """Regression guard for a bug this pack shipped with for about an hour.

    `mcp://{iam,secrets,vault}/**` compiles fine as literal characters and then
    matches nothing, forever. A dead allow is annoying; a dead *deny* is a
    security control that was never there and looks identical to one that is.
    """
    with pytest.raises(PolicyError, match="braces"):
        PolicyEngine.from_yaml(
            'version: 1\nrules:\n  - {id: r, match: {tool: "mcp://{a,b}/**"}, effect: deny}\n'
        )


def test_denies_precede_the_broad_read_allow():
    """The other bug from the same hour: within a tier it is first-match-wins,
    so a deny written after a broader allow never runs. Checked positionally
    because the behavioural test above would also pass if someone reordered
    them and narrowed the allow instead — this pins the intended structure."""
    doc = yaml.safe_load((PACKS / f"{OWASP}.yaml").read_text())
    ids = [r["id"] for r in doc["rules"]]
    broad_allow = ids.index("llm06-read-only-tools-allowed")
    for deny in ("llm06-no-iam-tools", "llm06-no-secrets-tools", "llm06-no-vault-tools"):
        assert ids.index(deny) < broad_allow, (
            f"{deny} is ordered after the broad read allow, so it never fires"
        )
