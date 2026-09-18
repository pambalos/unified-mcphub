"""build-01 — delegation chain, attestation predicates, minimum-grade rule.

Negative controls first, per the series standard. The one that matters most is
`test_chain_attestation_is_minimum`: its inverted form (returning the maximum)
must fail, because a chain that reported its *strongest* link would launder a
weak identity into a strong-looking one, which is worse than having no chain at
all.
"""

from __future__ import annotations

import itertools
import logging

import pytest

from unified_enforce.action import (
    Action,
    Hop,
    Principal,
    grade_at_least,
)
from unified_enforce.extauthz import ON_BEHALF_OF_HEADER, CheckInput, ExtAuthzCore
from unified_enforce.policy import Decision, PolicyEngine, Verdict

GRADES = ("assigned", "derived", "attested")


def _chain(*grades: str) -> Principal:
    """A principal delegated through `grades[:-1]`, with `grades[-1]` as the leaf."""
    root = Principal(id="user:root", kind="user", attestation=grades[0])
    current = root
    for i, grade in enumerate(grades[1:], start=1):
        current = current.delegate(id=f"agent:h{i}", attestation=grade)
    return current


def _act(principal: Principal, *, verb: str = "write") -> Action:
    return Action.build(principal=principal, tool="mcp://srv/tool", verb=verb, resource="res")


# --- §4 the minimum-grade rule ---------------------------------------------


@pytest.mark.parametrize("depth", [1, 2, 3, 4, 5])
def test_chain_attestation_is_minimum(depth: int) -> None:
    """Negative control. Every grade combination at depths 1-5 reports the minimum.

    Holds C3 and eval-03 N7. If `chain_grade()` is changed to return the maximum
    — or the leaf's own grade — this fails for every mixed chain, which is the
    property the test exists to pin.
    """
    for grades in itertools.product(GRADES, repeat=depth):
        principal = _chain(*grades)
        expected = min(grades, key=GRADES.index)
        assert principal.chain_grade() == expected, grades

        # And the inverted implementation would disagree wherever it could:
        # a mixed chain's max is not its min, so the control has teeth.
        if len(set(grades)) > 1:
            assert principal.chain_grade() != max(grades, key=GRADES.index)


def test_weakest_link_names_the_offending_hop() -> None:
    principal = _chain("attested", "assigned", "attested")
    weak = principal.weakest_link()
    assert weak is not None and weak.id == "agent:h1"
    assert principal.chain_grade() == "assigned"


def test_leaf_can_be_the_weakest_link() -> None:
    """A weak leaf behind strong hops has no offending *hop* — and must say so."""
    principal = _chain("attested", "attested", "assigned")
    assert principal.chain_grade() == "assigned"
    assert principal.weakest_link() is None


def test_grade_ordering() -> None:
    assert grade_at_least("attested", "derived")
    assert grade_at_least("derived", "derived")
    assert not grade_at_least("assigned", "derived")


# --- §3 establishment, not assertion ---------------------------------------


def test_child_asserted_parent_is_dropped(caplog: pytest.LogCaptureFixture) -> None:
    """An inbound request carrying `on_behalf_of` is stripped and logged.

    Holds N6/N7's establishment half: the resolved chain contains only hops the
    parent's own credentialed context established, which at the gateway means
    none at all.
    """
    engine = PolicyEngine.from_dict(
        {"version": 1, "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}]}
    )
    core = ExtAuthzCore(enforcer=_enforcer(engine))
    with caplog.at_level(logging.WARNING, logger="unified_enforce.extauthz"):
        result = core.check(
            CheckInput(
                principal_id="agent:child",
                method="POST",
                path="/x",
                host="h",
                scheme="https",
                headers={ON_BEHALF_OF_HEADER: '[{"id":"user:victim","attestation":"attested"}]'},
            )
        )
    assert result.action is not None
    assert result.action.principal.chain() == []
    assert result.action.principal.chain_grade() == "assigned"
    assert result.action.context.extra["identity_assertion"] == ("on_behalf_of header dropped")
    assert "dropped caller-asserted delegation chain" in caplog.text


def test_delegate_stamps_the_parent_not_the_child() -> None:
    """The chain is what the spawning side says about itself, root-first."""
    root = Principal(id="user:b", kind="user", attestation="attested")
    child = root.delegate(id="agent:planner", attestation="derived")
    grandchild = child.delegate(id="agent:exec", attestation="derived")

    assert [h.id for h in grandchild.chain()] == ["user:b", "agent:planner"]
    assert grandchild.chain()[0].kind == "user"
    assert grandchild.lineage() == ["agent:exec", "agent:planner", "user:b"]


# --- §5 attestation as a policy predicate ----------------------------------


def _enforcer(engine: PolicyEngine):
    from unified_enforce.enforcer import Enforcer

    return Enforcer(engine)


def test_attestation_floor_denies_below() -> None:
    """A floor of `derived` denies an `assigned` chain and allows a `derived` one;
    the `why` names the failing hop."""
    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "attestation_floors": [
                {"id": "writes-need-derived", "match": {"verb": "write"}, "minimum": "derived"}
            ],
            "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}],
        }
    )

    weak = engine.decide(_act(_chain("attested", "assigned", "attested")))
    assert weak.verdict is Verdict.DENY
    assert weak.source == "attestation_floor"
    assert weak.rule_id == "writes-need-derived"
    detail = weak.context["attestation_below_floor"]
    assert detail["required"] == "derived"
    assert detail["chain_grade"] == "assigned"
    assert detail["offending_hop"]["id"] == "agent:h1"
    assert "agent:h1" in weak.reason

    strong = engine.decide(_act(_chain("attested", "derived", "attested")))
    assert strong.verdict is Verdict.ALLOW


def test_attestation_floor_can_defer_instead_of_deny() -> None:
    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "attestation_floors": [
                {"id": "f", "match": {}, "minimum": "attested", "effect": "defer"}
            ],
            "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}],
        }
    )
    assert engine.decide(_act(_chain("derived"))).verdict is Verdict.DEFER


def test_attestation_floor_reads_the_chain_not_the_leaf() -> None:
    """The laundering case: a perfectly attested leaf behind one weak hop.

    Reading `principal.attestation` here instead of `chain_grade()` would allow
    this, which is precisely the failure §4 exists to prevent.
    """
    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "attestation_floors": [{"id": "f", "match": {}, "minimum": "attested"}],
            "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}],
        }
    )
    laundered = _chain("attested", "assigned", "attested")
    assert laundered.attestation == "attested"
    assert engine.decide(_act(laundered)).verdict is Verdict.DENY


def test_constitutional_outranks_the_attestation_floor() -> None:
    """A floor may never waive a constitutional rule — the existing `floors`
    tier is already subordinate to it, and a second kind that outranked it would
    make "constitutional" mean two different things."""
    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "constitutional": [{"id": "c", "match": {}, "effect": "deny"}],
            "attestation_floors": [
                {"id": "f", "match": {}, "minimum": "attested", "effect": "defer"}
            ],
            "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}],
        }
    )
    decision = engine.decide(_act(_chain("assigned")))
    assert decision.verdict is Verdict.DENY
    assert decision.source == "constitutional"


def test_undelegated_principal_is_judged_on_its_own_grade() -> None:
    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "attestation_floors": [{"id": "f", "match": {}, "minimum": "derived"}],
            "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}],
        }
    )
    assert (
        engine.decide(_act(Principal(id="agent:solo", attestation="derived"))).verdict
        is Verdict.ALLOW
    )
    denied = engine.decide(_act(Principal(id="agent:solo", attestation="assigned")))
    assert denied.verdict is Verdict.DENY
    assert denied.context["attestation_below_floor"]["offending_hop"] is None


# --- §2 canonicalization ----------------------------------------------------


def test_chain_is_canonical() -> None:
    """A chain round-trips through canonical bytes identically, and `None` /
    `[]` produce the same digest. Holds the C2 dependency."""
    absent = Principal(id="agent:x", attestation="derived")
    empty = Principal(id="agent:x", attestation="derived", on_behalf_of=[])
    assert "on_behalf_of" not in absent.model_dump(mode="json")
    assert absent.model_dump(mode="json") == empty.model_dump(mode="json")

    a = _act(absent)
    b = Action(**{**a.model_dump(mode="json"), "principal": empty.model_dump(mode="json")})
    assert a.digest() == b.digest()

    chained = _chain("attested", "derived")
    action = _act(chained)
    reloaded = Action.model_validate_json(action.model_dump_json())
    assert reloaded.digest() == action.digest()
    assert reloaded.principal.chain_grade() == chained.chain_grade()


def test_adding_the_chain_did_not_move_existing_digests() -> None:
    """The compatibility claim, pinned: a principal with no delegation
    serializes to exactly the fields it did before build-01."""
    assert set(Principal(id="agent:x").model_dump(mode="json")) == {
        "id",
        "kind",
        "session_id",
        "labels",
        "attestation",
        "parent_id",
    }


# --- §6 human-rootedness ----------------------------------------------------


def test_non_human_root_is_flagged() -> None:
    """An agent-rooted chain sets the flag; a user-rooted one does not. It is a
    field, not a score — a cron with no human root is legitimate and must be
    visible as a distinct class rather than blended into one."""
    human = Principal(id="user:b", kind="user", attestation="attested").delegate(id="agent:worker")
    autonomous = Principal(id="agent:cron", attestation="derived").delegate(id="agent:worker")
    assert human.human_rooted()
    assert not autonomous.human_rooted()
    assert Principal(id="service:sched", kind="service").human_rooted()
    assert not Principal(id="agent:solo").human_rooted()


# --- parent_id compatibility ------------------------------------------------


def test_legacy_parent_id_reads_as_an_assigned_hop() -> None:
    """A parent recorded without a grade is a parent whose delegation was never
    established, and §4's honest reading of an unknown grade is the weakest one."""
    legacy = Principal(id="agent:child", attestation="attested", parent_id="user:b")
    assert [h.id for h in legacy.chain()] == ["user:b"]
    assert legacy.chain()[0].attestation == "assigned"
    assert legacy.chain_grade() == "assigned"
    assert legacy.lineage() == ["agent:child", "user:b"]
    assert legacy.human_rooted()


def test_chain_wins_over_parent_id() -> None:
    both = Principal(
        id="agent:child",
        parent_id="agent:stale",
        on_behalf_of=[Hop(id="user:b", kind="user", attestation="attested")],
    )
    assert [h.id for h in both.chain()] == ["user:b"]


# --- regressions from the build-01 self-review -----------------------------
#
# Five defects survived the twenty tests above. Each gets a test that fails
# against the original implementation, because a fix without one is a fix that
# comes back.


def test_delegate_sets_parent_id_for_legacy_consumers() -> None:
    """`delegate()` writes the chain AND the legacy one-level field.

    Leaving `parent_id` at None told every pre-chain consumer the principal was
    an orphan while `on_behalf_of` said otherwise — worse than the field being
    coarse, because the two disagreed.
    """
    root = Principal(id="user:b", kind="user", attestation="attested")
    child = root.delegate(id="agent:planner", attestation="derived")
    grandchild = child.delegate(id="agent:exec", attestation="attested")

    assert child.parent_id == "user:b"
    assert grandchild.parent_id == "agent:planner"  # the IMMEDIATE parent
    assert [h.id for h in grandchild.chain()] == ["user:b", "agent:planner"]


def test_evidence_ships_the_chain_grade_not_the_leaf() -> None:
    """The laundering §4 prevents on the decision side, prevented on the wire.

    Shipping `principal.attestation` made an `attested` leaf behind an
    `assigned` hop arrive as `attestation: "attested"` — a receiver counting
    denials per principal scored an unproven chain as proven.
    """
    from unified_enforce.evidence import summarise

    laundered = _chain("attested", "assigned", "attested")
    assert laundered.attestation == "attested"
    assert laundered.chain_grade() == "assigned"

    record = summarise(_act(laundered), Decision(Verdict.DENY, "r", "exact"))
    assert record["attestation"] == "assigned"
    assert record["parent_id"] == "agent:h1"


def test_args_scoped_attestation_floor_does_not_overmatch() -> None:
    """A floor scoped by `match.args` applies only where the args match.

    `_attestation_check` re-implemented tier matching and omitted the args
    step, so the constraint was dead — and silently, because the args map still
    compiled.
    """
    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "attestation_floors": [
                {
                    "id": "etc-needs-attested",
                    "match": {"verb": "write", "args": {"path": {"starts_with": ["/etc"]}}},
                    "minimum": "attested",
                }
            ],
            "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}],
        }
    )
    weak = _chain("assigned")

    outside = Action.build(
        principal=weak, tool="mcp://s/t", verb="write", resource="r", params={"path": "/home/ok"}
    )
    assert engine.decide(outside).verdict is Verdict.ALLOW

    inside = Action.build(
        principal=weak, tool="mcp://s/t", verb="write", resource="r", params={"path": "/etc/shadow"}
    )
    assert engine.decide(inside).verdict is Verdict.DENY


def test_human_rooted_infers_kind_from_the_id_prefix() -> None:
    """Production constructors never pass `kind`.

    The gateway, the hub and the authz resolver all build
    `Principal(id=..., attestation=...)` and leave `kind` at its `agent`
    default, so reading the field alone reported an OIDC-resolved `user:alice`
    as a non-human-rooted agent.
    """
    oidc_resolved = Principal(id="user:alice", attestation="derived")  # no kind=
    assert oidc_resolved.kind == "agent"  # the default the constructor left
    assert oidc_resolved.human_rooted()

    assert Principal(id="service:sched", attestation="derived").human_rooted()
    assert not Principal(id="agent:cron", attestation="derived").human_rooted()

    delegated = Principal(id="user:alice", attestation="attested").delegate(id="agent:worker")
    assert delegated.human_rooted()


def test_decision_context_reaches_the_audit_chain(tmp_path) -> None:
    """The offending hop is written down, not left in-process.

    A `why` that names which link failed is worth nothing to an investigator
    reading the chain a week later if it never left the process that computed
    it.
    """
    from unified_enforce.audit import AuditChain

    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "attestation_floors": [{"id": "f", "match": {}, "minimum": "attested"}],
            "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}],
        }
    )
    action = _act(_chain("attested", "assigned", "attested"))
    decision = engine.decide(action)
    assert decision.context is not None

    chain = AuditChain(tmp_path)
    chain.start()
    entry = chain.append_decision(action, decision)
    assert entry["payload"]["context"]["attestation_below_floor"]["offending_hop"]["id"] == (
        "agent:h1"
    )


def test_plain_decision_has_no_context_key(tmp_path) -> None:
    """Omitted when absent, like `counters` — the common entry stays clean."""
    from unified_enforce.audit import AuditChain

    engine = PolicyEngine.from_dict(
        {"version": 1, "rules": [{"id": "allow-all", "match": {}, "effect": "allow"}]}
    )
    action = _act(_chain("attested"))
    chain = AuditChain(tmp_path)
    chain.start()
    entry = chain.append_decision(action, engine.decide(action))
    assert "context" not in entry["payload"]
