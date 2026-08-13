"""Cumulative budgets, and the two ways they are usually fake. UAI-147.

A budget is fake if it can be reset, and it is fake if enforcing it costs the
property that made local enforcement possible. So the tests worth reading first
are `test_a_restart_does_not_re_arm_the_budget` and
`test_the_engine_still_does_no_io_and_holds_nothing` — the rest is arithmetic.

The third failure mode is subtler and has its own test: recovery that reads the
*stored* action rather than the recorded delta. A payments policy plausibly
redacts amounts, and a budget rebuilt from a redacted chain is a budget of zero
that looks entirely healthy.
"""

from __future__ import annotations

import time

import pytest

from unified_enforce import Action, PolicyEngine, Principal
from unified_enforce.audit import AuditChain
from unified_enforce.counters import DAY_BUCKETS, Counters
from unified_enforce.enforcer import Enforcer

POLICY = {
    "version": 1,
    "rules": [
        {
            "id": "budget",
            "match": {"tool": "sdk://payments/refund"},
            "when": "count.spend.day + double(params.amount) > 1000.0",
            "effect": "deny",
        },
        {"id": "refunds", "match": {"tool": "sdk://payments/refund"}, "effect": "allow"},
        {"id": "reads", "match": {"tool": "sdk://files/read"}, "effect": "allow"},
    ],
    "counters": [
        {
            "id": "spend",
            "match": {"tool": "sdk://payments/refund"},
            "value": "double(params.amount)",
            "on_verdict": "allow",
        },
        {"id": "denies", "on_verdict": "deny"},
    ],
}


def refund(amount: str = "100.00", principal: str = "agent:1") -> Action:
    return Action.build(
        principal=Principal(id=principal),
        tool="sdk://payments/refund",
        verb="create",
        resource="*",
        params={"amount": amount},
    )


def enforcer(tmp_path=None, **kw) -> Enforcer:
    chain = None
    if tmp_path is not None:
        chain = AuditChain(tmp_path)
        chain.start()
    return Enforcer(PolicyEngine.from_dict(POLICY), chain=chain, **kw)


# --- the property the whole thing rests on ------------------------------------


def test_the_engine_still_does_no_io_and_holds_nothing():
    """Counting must not have put state back in the engine.

    The <10 ms budget and the fail-closed story both depend on `decide()` being
    a pure function of its arguments — no lookup means no lookup that can be
    made to hang. So the same engine, asked the same question with different
    totals, answers differently; and asked twice with the same totals, answers
    identically. That is what "counters are an argument, not a lookup" means
    operationally.
    """
    engine = PolicyEngine.from_dict(POLICY)
    action = refund("900.00")

    empty = engine.decide(action, {"spend": {"day": 0.0}})
    spent = engine.decide(action, {"spend": {"day": 500.0}})
    again = engine.decide(action, {"spend": {"day": 500.0}})

    assert empty.verdict.value == "allow"
    assert spent.verdict.value == "deny"
    assert again.verdict.value == spent.verdict.value

    # And nothing accumulated in the engine from having been asked.
    assert engine.decide(action, {"spend": {"day": 0.0}}).verdict.value == "allow"


def test_a_policy_with_no_counters_does_not_pay_for_them():
    engine = PolicyEngine.from_dict({"version": 1, "rules": [{"id": "r", "effect": "allow"}]})
    assert engine.counter_ids == []
    assert engine.deltas(refund(), engine.decide(refund())) == {}


# --- the budget itself ---------------------------------------------------------


def test_individually_compliant_calls_add_up():
    """The OWASP gap in one test: ten $100 refunds against a $1,000 day."""
    e = enforcer()

    verdicts = [e.enforce(refund("100.00")).verdict.value for _ in range(11)]

    assert verdicts[:10] == ["allow"] * 10, "a budget that denies early is a broken rule"
    assert verdicts[10] == "deny"


def test_a_denied_action_does_not_spend_the_budget():
    """Otherwise a blocked agent exhausts its own budget by being blocked, and
    the denials themselves become the reason the next legitimate call fails."""
    e = enforcer()

    for _ in range(20):
        e.enforce(refund("2000.00"))  # over the day on its own; denied every time

    assert e.enforce(refund("100.00")).verdict.value == "allow"


def test_one_principal_does_not_spend_anothers_budget():
    e = enforcer()

    for _ in range(11):
        e.enforce(refund("100.00", principal="agent:1"))

    assert e.enforce(refund("100.00", principal="agent:2")).verdict.value == "allow"


def test_denies_are_counted_for_the_rogue_signal():
    """The same mechanism, read by the control plane rather than by a rule
    (UAI-167). Built once because it is one missing thing, not two."""
    e = enforcer()

    e.enforce(refund("100.00"))
    for _ in range(3):
        e.enforce(refund("5000.00"))

    totals = e.counters.snapshot("agent:1", ["spend", "denies"])
    assert totals["denies"]["day"] == 3.0
    assert totals["spend"]["day"] == 100.0


# --- restart --------------------------------------------------------------------


def test_a_restart_does_not_re_arm_the_budget(tmp_path):
    """The attack, not the inconvenience.

    An agent that can crash its own sidecar can spend the daily limit once per
    restart, which is not a daily limit. Recovery reads the chain, which is
    signed and append-only and was already recording every decision.
    """
    first = enforcer(tmp_path)
    for _ in range(9):
        assert first.enforce(refund("100.00")).verdict.value == "allow"
    first._chain.stop()  # the chain takes an exclusive lock; a restart releases it

    second = enforcer(tmp_path)
    assert second.recover_counters() > 0
    assert second.enforce(refund("100.00")).verdict.value == "allow"  # the tenth
    assert second.enforce(refund("100.00")).verdict.value == "deny"  # the eleventh


def test_recovery_survives_a_policy_that_redacts_the_amount(tmp_path):
    """The subtle one, and the reason the delta is written into the entry.

    Rebuilt from the *stored* action, this budget would come back as zero: a
    payments policy plausibly redacts `params`, and the recovered total would
    look perfectly healthy while being wrong by the entire day's spend.
    """
    policy = {
        **POLICY,
        "rules": [
            {**POLICY["rules"][0]},
            {**POLICY["rules"][1], "audit_level": "minimal"},
            *POLICY["rules"][2:],
        ],
    }
    chain = AuditChain(tmp_path)
    chain.start()
    first = Enforcer(PolicyEngine.from_dict(policy), chain=chain)
    for _ in range(9):
        first.enforce(refund("100.00"))

    stored = [e for e in chain.entries() if e["payload"].get("counters")]
    assert stored, "no counter deltas were recorded"
    assert stored[0]["payload"]["action"]["params"] is None, "this test needs a redacted action"
    chain.stop()

    chain2 = AuditChain(tmp_path)
    chain2.start()
    second = Enforcer(PolicyEngine.from_dict(policy), chain=chain2)
    second.recover_counters()

    assert second.counters.snapshot("agent:1", ["spend"])["spend"]["day"] == 900.0


def test_recovery_ignores_entries_older_than_the_window(tmp_path):
    """Yesterday's spend credited to today would deny an agent for a day it
    has not had yet."""
    counters = Counters()
    old = time.time() - 60 * (DAY_BUCKETS + 60)

    from datetime import UTC, datetime

    applied = counters.replay(
        [
            {
                "ts": datetime.fromtimestamp(old, UTC).isoformat(),
                "payload": {
                    "action": {"principal": {"id": "agent:1"}},
                    "counters": {"spend": 900.0},
                },
            }
        ]
    )

    assert applied == 0
    assert counters.snapshot("agent:1", ["spend"])["spend"]["day"] == 0.0


def test_recovery_does_not_stop_a_sidecar_starting_on_a_truncated_chain(tmp_path):
    """What an unclean shutdown leaves behind. Refusing to start because the
    last line is half-written would turn a crash into an outage."""
    e = enforcer(tmp_path)
    e.enforce(refund("100.00"))
    e._chain.stop()

    log = sorted(tmp_path.glob("*.jsonl"))[0]
    log.write_text(log.read_text() + '{"ts": "2026-01-01T00:00:00+00:00", "payl')

    assert enforcer(tmp_path).recover_counters() >= 1


# --- windows ---------------------------------------------------------------------


def test_the_three_windows_are_nested_not_independent():
    counters = Counters()
    now = time.time()

    counters.add("agent:1", "spend", 10.0, now=now - 3600 * 5)  # 5h ago
    counters.add("agent:1", "spend", 20.0, now=now - 600)  # 10m ago
    counters.add("agent:1", "spend", 30.0, now=now)

    totals = counters.snapshot("agent:1", ["spend"], now=now)["spend"]
    assert totals["minute"] == 30.0
    assert totals["hour"] == 50.0
    assert totals["day"] == 60.0


def test_a_series_does_not_grow_without_bound():
    """A hot principal must cost the same as a quiet one, or the decision path
    allocates more the busier it gets."""
    counters = Counters()
    start = time.time() - 60 * DAY_BUCKETS * 2

    for i in range(DAY_BUCKETS * 2):
        counters.add("agent:1", "spend", 1.0, now=start + i * 60)

    series = counters._series[("agent:1", "spend")]
    assert len(series._buckets) <= DAY_BUCKETS


def test_a_declared_counter_always_resolves_to_a_number():
    """A missing id would make the CEL referencing it raise, which becomes a
    deny — the safe direction, and impossible to debug from the outside."""
    totals = Counters().snapshot("agent:never-seen", ["spend", "denies"])

    assert totals["spend"] == {"minute": 0.0, "hour": 0.0, "day": 0.0}
    assert set(totals) == {"spend", "denies"}


def test_eviction_is_counted_because_it_re_arms_a_budget(caplog):
    """Not silent. Eviction zeroes a total, which is a fail-open, and the cap
    is set where only a wrong assumption reaches it."""
    counters = Counters(max_series=2)

    for i in range(4):
        counters.add(f"agent:{i}", "spend", 1.0)

    assert counters.evictions == 2
    assert counters.snapshot("agent:0", ["spend"])["spend"]["day"] == 0.0


# --- what the counter costs -------------------------------------------------------


@pytest.mark.parametrize("declared", [0, 2])
def test_counting_does_not_blow_the_latency_budget(declared):
    """The whole design exists to keep the decision path cheap; a counter that
    cost milliseconds would have defeated the point of avoiding a network hop.

    A loose bound deliberately — this runs on laptops and shared CI — but far
    below the 10 ms budget, so a regression that turns a dict lookup into
    something expensive still fails it.
    """
    policy = POLICY if declared else {"version": 1, "rules": POLICY["rules"]}
    e = enforcer()
    e._engine = PolicyEngine.from_dict(policy)

    for _ in range(200):  # warm
        e.enforce(refund("1.00"))

    start = time.perf_counter()
    for _ in range(1000):
        e.enforce(refund("1.00"))
    per_call_ms = (time.perf_counter() - start) * 1000 / 1000

    assert per_call_ms < 2.0, f"{per_call_ms:.3f}ms per decision with {declared} counters"
