"""Shadow mode: measure a proposal, never obey it.

Two invariants dominate, and both would be catastrophic to get wrong in the
quiet way — a candidate that silently enforces is unreviewed policy in
production, and a candidate that can break a decision makes shadow mode more
dangerous than the change it exists to de-risk.

So most of this file is about what shadow mode must *not* do. The divergence
counting is the easy part.
"""

from __future__ import annotations

import pytest

from unified_enforce import Action, Principal
from unified_enforce.enforcer import Enforcer
from unified_enforce.policy import PolicyEngine
from unified_enforce.shadow import ShadowEvaluator

STRICT = b"""
version: 1
rules:
  - id: no-payments
    match: {tool: "sdk://payments/**"}
    effect: deny
  - id: reads-ok
    match: {tool: "**"}
    effect: allow
"""

LOOSE = b"""
version: 1
rules:
  - id: everything-ok
    match: {tool: "**"}
    effect: allow
"""

STRICTER = b"""
version: 1
rules:
  - id: nothing-doing
    match: {tool: "**"}
    effect: deny
"""


def action(tool="sdk://payments/refund", principal="agent:payments-1") -> Action:
    return Action.build(
        principal=Principal(id=principal),
        tool=tool,
        verb="create",
        resource="*",
        params={"amount": "12400.00"},
    )


def enforcing() -> PolicyEngine:
    return PolicyEngine.from_yaml(STRICT.decode())


def evaluator(files: bytes, version: int = 2) -> ShadowEvaluator:
    shadow = ShadowEvaluator()
    assert shadow.load({"base.yaml": files}, version)
    return shadow


# --- a candidate never changes a verdict ---------------------------------------


@pytest.mark.parametrize("candidate", [LOOSE, STRICTER], ids=["looser", "stricter"])
def test_the_enforced_verdict_is_identical_with_and_without_a_candidate(candidate):
    """The property that makes shadow mode safe to switch on.

    A candidate that would allow everything, and one that would deny
    everything, must both leave the actual decision untouched.
    """
    plain = Enforcer(enforcing()).enforce(action())
    shadowed = Enforcer(enforcing(), shadow=evaluator(candidate)).enforce(action())

    assert plain.verdict == shadowed.verdict
    assert plain.rule_id == shadowed.rule_id


def test_a_candidate_that_raises_does_not_break_enforcement():
    """A defect in a proposal must not become a failed enforcement.

    Otherwise proposing a change is riskier than making one, and nobody would
    use shadow mode for the edits that most need it.
    """

    class Exploding:
        def decide(self, action):
            raise RuntimeError("bad rule")

    shadow = ShadowEvaluator()
    shadow._engine = Exploding()  # noqa: SLF001 - simulating a compiled-but-broken policy
    shadow._version = 2  # noqa: SLF001

    decision = Enforcer(enforcing(), shadow=shadow).enforce(action())

    assert decision.verdict.value == "deny"
    assert shadow.errors == 1


def test_a_candidate_that_does_not_compile_is_refused_at_load():
    """Loudly, and at load — not as an exception on every request.

    A candidate that will not compile is itself a finding: it is what would
    have happened had somebody promoted it.
    """
    shadow = ShadowEvaluator()
    assert not shadow.load({"base.yaml": b"this: is: not: policy"}, 2)

    # And it evaluates nothing rather than half-working.
    assert shadow.compare(action(), Enforcer(enforcing()).enforce(action())) is None


def test_a_multi_file_candidate_is_refused_rather_than_guessed_at():
    """Merging differently from the enforcing loader would make the divergence
    report a report about the merge order, not about the policy."""
    shadow = ShadowEvaluator()
    assert not shadow.load({"a.yaml": STRICT, "b.yaml": LOOSE}, 2)


# --- divergences ----------------------------------------------------------------


def test_a_looser_candidate_reports_what_it_would_newly_allow():
    """The direction that needs justifying.

    A proposal that would newly permit something currently denied is the one an
    operator must argue for; burying it in a total would hide it.
    """
    shadow = evaluator(LOOSE)
    enforcer = Enforcer(enforcing(), shadow=shadow)

    enforcer.enforce(action())  # denied today, allowed by the candidate
    enforcer.enforce(action(tool="mcp://github/list_prs"))  # allowed by both

    summary = shadow.summary()
    assert summary["compared"] == 2
    assert summary["divergences"] == 1
    assert summary["would_newly_allow"] == 1
    assert summary["would_newly_deny"] == 0


def test_a_stricter_candidate_reports_what_it_would_newly_deny():
    """The direction that breaks things.

    Too strict is the other half of a bad policy edit, and it shows up as
    denials of work that currently succeeds.
    """
    shadow = evaluator(STRICTER)
    enforcer = Enforcer(enforcing(), shadow=shadow)

    enforcer.enforce(action(tool="mcp://github/list_prs"))
    enforcer.enforce(action())

    summary = shadow.summary()
    assert summary["would_newly_deny"] == 1
    assert summary["would_newly_allow"] == 0


def test_agreement_is_recorded_as_agreement_not_as_silence():
    """ "No divergences" and "the candidate never ran" are different findings.

    The first says a proposal is equivalent on observed traffic; the second
    says nothing was learned, and promoting on it would be promoting on an
    absence of evidence.
    """
    shadow = evaluator(STRICT)
    enforcer = Enforcer(enforcing(), shadow=shadow)
    for _ in range(5):
        enforcer.enforce(action())

    summary = shadow.summary()
    assert summary["compared"] == 5
    assert summary["divergences"] == 0

    never_ran = ShadowEvaluator().summary()
    assert never_ran["compared"] == 0
    assert never_ran["divergences"] == 0
    assert never_ran["shadow_version"] is None


def test_a_divergence_names_both_rules():
    """Which rule fired on each side is the whole diagnostic.

    "This would change" is a fact; "this would change because `reads-ok` now
    matches where `no-payments` used to" is something an author can act on.
    """
    shadow = evaluator(LOOSE)
    Enforcer(enforcing(), shadow=shadow).enforce(action())

    d = shadow.divergences[0]
    assert (d.enforced, d.proposed) == ("deny", "allow")
    assert d.enforced_rule == "no-payments"
    assert d.proposed_rule == "everything-ok"
    assert d.shadow_version == 2


def test_divergence_records_carry_no_action_content():
    """They travel to a control plane, so the evidence rule applies.

    The digest is how an investigator reaches the parameters, in the customer's
    own chain where they already are.
    """
    shadow = evaluator(LOOSE)
    a = action()
    Enforcer(enforcing(), shadow=shadow).enforce(a)

    record = shadow.divergences[0].as_record()
    assert record["action_digest"] == a.digest()
    assert "12400.00" not in repr(record)
    assert "params" not in record


# --- lifecycle -------------------------------------------------------------------


def test_loading_a_new_candidate_discards_the_previous_findings():
    """Divergences belong to the proposal that produced them.

    Carrying them across would have an operator promoting v3 on evidence
    gathered about v2.
    """
    shadow = evaluator(LOOSE, version=2)
    Enforcer(enforcing(), shadow=shadow).enforce(action())
    assert shadow.summary()["divergences"] == 1

    assert shadow.load({"base.yaml": STRICT}, 3)
    assert shadow.summary() == {
        "shadow_version": 3,
        "compared": 0,
        "divergences": 0,
        "would_newly_allow": 0,
        "would_newly_deny": 0,
        "errors": 0,
    }


def test_reloading_the_same_version_keeps_its_findings():
    """A refresh is not a new proposal.

    Clearing on every poll would mean a candidate never accumulated enough
    observations to be worth reading.
    """
    shadow = evaluator(LOOSE, version=2)
    Enforcer(enforcing(), shadow=shadow).enforce(action())

    assert shadow.load({"base.yaml": LOOSE}, 2)
    assert shadow.summary()["divergences"] == 1


def test_clearing_stops_evaluation_entirely():
    """When a candidate is promoted or withdrawn there is nothing left to
    measure, and continuing would report against a question nobody is asking."""
    shadow = evaluator(LOOSE)
    shadow.clear()

    enforcer = Enforcer(enforcing(), shadow=shadow)
    assert enforcer.enforce(action()).verdict.value == "deny"
    assert shadow.summary()["compared"] == 0
