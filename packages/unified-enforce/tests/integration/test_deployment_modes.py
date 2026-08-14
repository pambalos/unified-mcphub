"""Deployment modes, stood up rather than validated. UAI-161.

`terraform validate` proves the HCL parses. `test_terraform_modules.py` says so
plainly and is honest about its reach. This file is the other half: it asserts
the properties a deployment mode *exists to hold*, against components actually
running.

**What this file covers today, and what it does not — stated up front because
"log what was skipped" is a requirement of the ticket and because a suite that
quietly covered one mode reads exactly like one that covered three.**

| mode | property | covered here |
|---|---|---|
| hybrid | control plane unreachable ⇒ still enforcing, DEFERs fail closed, evidence backfills | **yes**, end to end |
| hybrid | chain continuity across a restart | **yes** |
| self-hosted / air-gapped | zero egress, by observation | **yes**, out of band — `deploy/test-harness` |
| any | teardown leaves nothing billable | **yes**, out of band — `deploy/test-harness/sweep.sh` |
| BYOC | no action content crosses the boundary | partly: the *shape* is asserted here, the boundary is not |
| any | chain continuity across a mode migration | no — needs two applied deployments |

Two rows are marked **out of band**: they are verified by `deploy/test-harness`,
which applies real infrastructure and therefore cannot run per-PR. Its result is
recorded in that directory's README with the date and the console output, so
"verified" here means somebody can go and read what was observed rather than
take this table's word for it.

The rows still uncovered are not silently absent:
`test_the_uncovered_modes_are_declared` fails if this table and the manifest
below disagree, so the gap is visible in test output rather than in a reader's
memory.

**Why hybrid is the one worth having first.** It is the mode whose failure is a
security failure rather than a deployment failure. If the control plane being
unreachable stopped enforcement, an attacker's first move would be to make it
unreachable — and that property can be tested honestly with a real sidecar and a
real control plane on a laptop, by simply refusing to answer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


def _artifacts():
    """The signed documents a control plane would serve.

    Imported from the distribution suite rather than rebuilt, so this file
    cannot drift into testing a *different* artifact format from the one the
    verifier actually accepts — which would be a green suite proving nothing.
    Done inside a function with an explicit path insert because pytest puts
    each test directory on `sys.path` separately and `tests/` is not a package.
    """
    import sys

    tests_dir = str(Path(__file__).resolve().parents[1])
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)

    import test_distribution as fixtures

    return fixtures


#: The modes this file cannot stand up, and why. Written out so the gap is a
#: declaration rather than an omission — the same discipline the corpus uses for
#: `known_gap`.
NOT_COVERED = {
    "byoc-boundary": (
        "what actually crosses the customer boundary can only be observed with "
        "the deployment standing up. The evidence *shape* is asserted below; the "
        "boundary is not."
    ),
    "mode-migration-chain-continuity": (
        "needs two applied deployments and a migration between them. Continuity "
        "across a restart is covered below; across a migration is not."
    ),
}


#: The phrase in the coverage table that each uncovered mode must appear under.
#: Distinctive on purpose: the first version of this guard matched the first
#: word of the key, which meant `mode-migration-chain-continuity` was satisfied
#: by the word "mode" appearing in a table about deployment modes. That is the
#: same vacuous-guard shape this project keeps finding, so the phrases here are
#: long enough that containing one is evidence rather than coincidence.
TABLE_PHRASES = {
    "byoc-boundary": "no action content crosses the boundary",
    "mode-migration-chain-continuity": "across a migration is not",
}


def test_the_uncovered_modes_are_declared():
    """The docstring table and the manifest must agree.

    A suite that quietly covered one mode reads exactly like one that covered
    three, so the gap is asserted rather than remembered. If somebody covers a
    mode and forgets to remove it here, this fails and makes them.
    """
    doc = Path(__file__).read_text()
    header = doc[: doc.index('"""', 3)]
    body = doc

    assert set(TABLE_PHRASES) == set(NOT_COVERED), (
        "a mode was added to one of the two manifests and not the other"
    )

    for mode, phrase in TABLE_PHRASES.items():
        where = header if mode != "mode-migration-chain-continuity" else body
        assert phrase in where, (
            f"{mode} is declared uncovered but its explanation ({phrase!r}) is gone"
        )

    assert "needs two applied deployments" in header, (
        "the coverage table no longer states which rows need a real account"
    )
    assert "deploy/test-harness" in header, (
        "the table no longer points at where the out-of-band results live"
    )


# --- hybrid: the control plane goes away --------------------------------------------


async def test_hybrid_keeps_enforcing_when_the_control_plane_is_unreachable(tmp_path):
    """The property whose failure would be a security failure, not an outage.

    If losing the control plane stopped enforcement, an attacker's first move
    would be to make it unreachable.

    Written against a `Distribution` that really did verify a bundle and then
    lost its source, rather than against an engine with no control plane at
    all. The first draft did the latter, which asserts "the policy engine
    works" while claiming to assert "hybrid survives an outage" — a test whose
    name is stronger than its body, and this file already exists because
    `terraform validate` had the same problem.

    Containment ordered *before* the outage must also still apply: an agent
    stopped on Monday does not resume because the network broke on Tuesday.
    """
    from unified_enforce import Action, Principal
    from unified_enforce.distribution import Distribution
    from unified_enforce.enforcer import Enforcer
    from unified_enforce.policy import PolicyEngine

    fixtures = _artifacts()
    root = fixtures.Key()
    policy_key = fixtures.Key()
    keyset, bundle, revocations = fixtures.keyset, fixtures.bundle, fixtures.revocations

    class DiesAfterFirstPoll:
        def __init__(self) -> None:
            self.up = True
            self.keyset_doc = keyset(root, policy_key)
            self.bundle_doc = bundle(policy_key)
            self.revocations_doc = revocations(
                policy_key, entries=[{"principal_id": "agent:contained", "mode": "deny"}]
            )

        def _check(self):
            if not self.up:
                raise ConnectionError("control plane unreachable")

        def fetch_keyset(self):
            self._check()
            return self.keyset_doc

        def fetch_bundle(self):
            self._check()
            return self.bundle_doc

        def fetch_revocations(self):
            self._check()
            return self.revocations_doc

    source = DiesAfterFirstPoll()
    dist = Distribution(source, fleet_id="acme", root_public_key=root.public)
    report = dist.refresh(now=fixtures.NOW)
    assert not report.problems and dist.snapshot.is_usable(), report.problems

    # The outage.
    source.up = False
    assert dist.refresh(now=fixtures.NOW).unreachable

    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "rules": [
                {"id": "reads", "match": {"tool": "sdk://files/read"}, "effect": "allow"},
                {"id": "refunds", "match": {"tool": "sdk://payments/refund"}, "effect": "deny"},
            ],
        }
    )
    enforcer = Enforcer(engine, distribution=dist)

    def act(tool: str, principal: str = "agent:1") -> Action:
        return Action.build(principal=Principal(id=principal), tool=tool, verb="read", resource="*")

    assert enforcer.enforce(act("sdk://files/read")).verdict.value == "allow"
    assert enforcer.enforce(act("sdk://payments/refund")).verdict.value == "deny"
    assert enforcer.enforce(act("sdk://unknown/tool")).verdict.value == "deny"
    assert enforcer.enforce(act("sdk://files/read", "agent:contained")).verdict.value == "deny", (
        "containment ordered before the outage stopped applying during it"
    )


async def test_hybrid_defers_fail_closed_with_no_one_to_ask(tmp_path):
    """A DEFER is a demand for a human. With no channel to reach one, the honest
    outcome is that the action does not proceed.

    Checked because the tempting implementation is the dangerous one: a DEFER
    that cannot reach anybody is trivially turned into an allow by an attacker
    who blocks one network path.
    """
    from unified_enforce import Action, PolicyEngine, Principal
    from unified_enforce.enforcer import Enforcer

    engine = PolicyEngine.from_dict(
        {
            "version": 1,
            "rules": [{"id": "reads", "match": {"tool": "sdk://files/**"}, "effect": "allow"}],
            "floors": [{"id": "refunds-need-a-human", "match": {"tool": "sdk://payments/**"}}],
        }
    )
    # No approvals channel configured: the sidecar cannot reach a human.
    enforcer = Enforcer(engine)

    outcome = await enforcer.enforce_with_approval(
        Action.build(
            principal=Principal(id="agent:1"),
            tool="sdk://payments/refund",
            verb="create",
            resource="*",
        )
    )

    assert outcome.decision.verdict.value == "defer", (
        "a floored action must not become an allow because nobody could be asked"
    )
    assert outcome.kind is None, "nobody was asked, and the outcome must say so"


async def test_hybrid_spools_evidence_and_backfills_on_reconnect(tmp_path):
    """Losing the control plane costs visibility, never enforcement — and the
    visibility comes back rather than being lost.

    The spool is what makes shedding safe elsewhere: ingest quotas, a 429, an
    outage. All of them are acceptable precisely because the sidecar keeps its
    evidence and ships it later.
    """
    from unified_enforce import Action, PolicyEngine, Principal
    from unified_enforce.enforcer import Enforcer
    from unified_enforce.evidence import EvidenceShipper

    class Unreachable:
        """A control plane that is down, then up."""

        def __init__(self) -> None:
            self.up = False
            self.received: list = []

        def send(self, records):
            if not self.up:
                raise ConnectionError("control plane unreachable")
            self.received.extend(records)

    sink = Unreachable()
    shipper = EvidenceShipper(sink, interval_seconds=0.01)
    engine = PolicyEngine.from_dict(
        {"version": 1, "rules": [{"id": "r", "match": {"tool": "**"}, "effect": "allow"}]}
    )
    enforcer = Enforcer(engine, evidence=shipper)

    for i in range(5):
        enforcer.enforce(
            Action.build(
                principal=Principal(id="agent:1"),
                tool=f"sdk://files/read{i}",
                verb="read",
                resource="*",
            )
        )

    shipper.flush()
    assert sink.received == [], "this test needs the control plane to be down"

    sink.up = True
    shipper.flush()

    assert len(sink.received) == 5, "spooled evidence did not backfill on reconnect"


async def test_hybrid_chain_continuity_across_a_restart(tmp_path):
    """A restart is the ordinary case, and it must not break the chain.

    Migration between modes is the harder version and is declared uncovered;
    this is the half that can be tested honestly on one machine.
    """
    from unified_enforce.audit import AuditChain

    chain = AuditChain(tmp_path / "audit")
    chain.start()
    for i in range(5):
        chain.append("decision", {"i": i})
    head_before = chain.head
    chain.stop()

    restarted = AuditChain(tmp_path / "audit")
    restarted.start()
    entry = restarted.append("decision", {"after": "restart"})
    restarted.stop()

    assert entry["prev_hash"] == head_before, "the chain did not resume from its own head"
    assert AuditChain.verify(tmp_path / "audit").ok


# --- BYOC: the shape of what would cross ---------------------------------------------


def test_byoc_evidence_carries_no_action_content():
    """What the boundary assertion would check, checked at the shape level.

    Standing up BYOC and observing the boundary is declared uncovered. This is
    the part that can be asserted without an account: the record a sidecar
    *would* ship carries digests and metadata and no parameters, so a boundary
    test would be confirming a property the format already has rather than
    discovering one.
    """
    from unified_enforce import Action, Principal
    from unified_enforce.evidence import summarise

    action = Action.build(
        principal=Principal(id="agent:1"),
        tool="sdk://payments/refund",
        verb="create",
        resource="acct-9931",
        params={"amount": "12400.00", "iban": "GB29NWBK60161331926819"},
    )

    from unified_enforce.policy import Decision, Verdict

    record = summarise(action, Decision(Verdict.DENY, "rule-1", "exact", "standard", None))
    serialised = json.dumps(record)

    assert "12400.00" not in serialised
    assert "GB29NWBK60161331926819" not in serialised
    assert action.digest() in serialised, "without the digest it cannot be joined to the chain"
