"""The distribution failure matrix, row by row. Spec §5.

`test_attest.py` proves the verifier refuses bad artifacts. This proves the
sidecar does the right thing *about* a refusal — a separate question, and the
one where nearly every wrong answer is a fail-open.

The rule under test throughout:

    a distribution failure may cost freshness; it may never grant permission.

Each test names the situation from the matrix and asserts the behaviour, not
just the state, because the state is only interesting insofar as it changes
what an agent is allowed to do.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from unified_enforce.action import Action, Principal
from unified_enforce.attest import b64u, key_id, sign_bytes
from unified_enforce.distribution import (
    ControlPlaneSource,
    Poller,
    Distribution,
    Health,
    StaleAction,
)
from unified_enforce.policy import Verdict

NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
DAY = timedelta(days=1)
FLEET = "acme"
AGENT = "agent:payments-1"


class Key:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = b64u(self.private.public_key().public_bytes_raw())
        self.kid = key_id(self.public)

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


@pytest.fixture
def root() -> Key:
    return Key()


@pytest.fixture
def policy_key() -> Key:
    return Key()


def keyset(root: Key, policy_key: Key, *, now=NOW):
    payload = json.dumps(
        {
            "schema": "unified.keyset/v1",
            "issued_at_ms": ms(now),
            "expires_at_ms": ms(now + 7 * DAY),
            "keys": [
                {
                    "kid": policy_key.kid,
                    "alg": "EdDSA",
                    "role": "policy",
                    "public_key": policy_key.public,
                    "expires_at_ms": ms(now + 90 * DAY),
                }
            ],
        }
    ).encode()
    return sign_bytes(payload, root, root.kid)


def bundle(
    policy_key: Key, *, version=1, fleet=FLEET, now=NOW, ttl=DAY, files=None, mode="enforce"
):
    files = files if files is not None else {"base.yaml": b"default: deny\n"}
    import hashlib

    payload = json.dumps(
        {
            "schema": "unified.policy-bundle/v1",
            "fleet_id": fleet,
            "version": version,
            "issued_at_ms": ms(now),
            "expires_at_ms": ms(now + ttl),
            "mode": mode,
            "files": [
                {"path": p, "sha256": hashlib.sha256(c).hexdigest(), "size": len(c)}
                for p, c in sorted(files.items())
            ],
        }
    ).encode()
    return {
        "manifest": sign_bytes(payload, policy_key, policy_key.kid),
        "files": {p: c.decode() for p, c in files.items()},
    }


def revocations(policy_key: Key, *, version=1, entries=(), now=NOW, ttl=timedelta(minutes=15)):
    payload = json.dumps(
        {
            "schema": "unified.revocations/v1",
            "fleet_id": FLEET,
            "version": version,
            "issued_at_ms": ms(now),
            "expires_at_ms": ms(now + ttl),
            "revocations": list(entries),
        }
    ).encode()
    return {"revocations": sign_bytes(payload, policy_key, policy_key.kid)}


class FakeSource:
    """A source under the test's control, including its failures."""

    def __init__(self, keyset_doc, bundle_doc, revocations_doc):
        self.keyset_doc = keyset_doc
        self.bundle_doc = bundle_doc
        self.revocations_doc = revocations_doc
        self.down = False

    def _check(self):
        if self.down:
            raise ConnectionError("source unreachable")

    def fetch_keyset(self):
        self._check()
        return self.keyset_doc

    def fetch_bundle(self):
        self._check()
        return self.bundle_doc

    def fetch_revocations(self):
        self._check()
        return self.revocations_doc


@pytest.fixture
def source(root, policy_key):
    return FakeSource(keyset(root, policy_key), bundle(policy_key), revocations(policy_key))


def make(source, root, **kwargs) -> Distribution:
    return Distribution(source, fleet_id=FLEET, root_public_key=root.public, **kwargs)


def action(tool="sdk://payments/refund", principal=AGENT) -> Action:
    return Action.build(
        principal=Principal(id=principal, kind="agent"),
        tool=tool,
        verb="create",
        resource="*",
    )


# --- the happy path, so the negatives mean something --------------------------


def test_a_verified_bundle_makes_policy_fresh_and_gates_nothing(source, root):
    dist = make(source, root)
    report = dist.refresh(now=NOW)

    assert report.applied_bundle and report.applied_revocations
    assert not report.alarming()
    assert dist.snapshot.health is Health.FRESH
    assert dist.gate(action()) is None, "a fresh, uncontained agent must reach the policy engine"


# --- no bundle at all ---------------------------------------------------------


def test_a_sidecar_with_no_verified_policy_denies_everything(source, root):
    """The row people get wrong.

    Denying at startup looks like an outage, which is exactly why a permissive
    default is tempting — and why an attacker who can block one fetch would get
    an unprotected agent.
    """
    source.down = True
    dist = make(source, root)
    dist.refresh(now=NOW)

    assert dist.snapshot.health is Health.UNPROVISIONED
    forced = dist.gate(action())
    assert forced is not None
    assert forced.verdict == "deny"
    assert forced.source == "distribution"


def test_an_unverifiable_bundle_never_becomes_policy(source, root, policy_key):
    """A forged bundle leaves a fresh sidecar unprovisioned, not provisioned."""
    impostor = Key()
    source.bundle_doc = bundle(impostor)

    dist = make(source, root)
    report = dist.refresh(now=NOW)

    assert report.alarming()
    assert dist.snapshot.health is Health.UNPROVISIONED
    assert dist.gate(action()).verdict == "deny"


# --- unreachable --------------------------------------------------------------


def test_unreachable_keeps_the_last_bundle_and_does_not_alarm(source, root):
    """Brief unreachability is ordinary.

    Alarming on it trains an operator to ignore the alarm that means something,
    and expiry already covers the case where it stops being brief.
    """
    dist = make(source, root)
    dist.refresh(now=NOW)

    source.down = True
    report = dist.refresh(now=NOW + timedelta(minutes=5))

    assert report.unreachable
    assert not report.alarming(), "unreachability must not be an alarm on its own"
    assert dist.snapshot.health is Health.FRESH
    assert dist.gate(action()) is None


# --- staleness ----------------------------------------------------------------


def test_expired_policy_keeps_enforcing_by_default(source, root, policy_key):
    """Old rules are still rules.

    A network partition must not take down a customer's agents; the alarm is
    the operator's signal, not a change in what agents may do.

    The revocation list is kept fresh here on purpose. Taking the whole source
    down staleness *both* artifacts, and a stale revocation list escalates —
    so the test would pass while measuring the wrong thing. An earlier version
    did exactly that, and only the `on_stale=deny` case exposed it.
    """
    dist = make(source, root)
    dist.refresh(now=NOW)

    later = NOW + 2 * DAY
    source.revocations_doc = revocations(policy_key, version=2, now=later)
    dist.refresh(now=later)

    assert dist.snapshot.health is Health.STALE
    assert dist.snapshot.revocations_health is Health.FRESH
    assert dist.gate(action()) is None, "stale must not mean permissive *or* dead"


@pytest.mark.parametrize(
    "mode,verdict",
    [(StaleAction.DEFER, "defer"), (StaleAction.DENY, "deny")],
)
def test_stale_behaviour_is_configurable(source, root, policy_key, mode, verdict):
    """Spec §5.1 — the same axis as containment modes.

    An operator should not have to learn two vocabularies for "what happens
    when we are unsure".

    Revocations stay fresh so this isolates *policy* staleness; otherwise the
    `defer` case passes because of the revocation rule rather than `on_stale`.
    """
    dist = make(source, root, on_stale=mode)
    dist.refresh(now=NOW)

    later = NOW + 2 * DAY
    source.revocations_doc = revocations(policy_key, version=2, now=later)
    dist.refresh(now=later)

    forced = dist.gate(action())
    assert forced.verdict == verdict
    assert forced.source == "distribution"


# --- rejections that must not apply -------------------------------------------


def test_a_rollback_is_refused_and_alarms(source, root, policy_key):
    """Genuinely signed, genuinely old. This is an attack, not a mistake."""
    dist = make(source, root)
    source.bundle_doc = bundle(policy_key, version=5)
    dist.refresh(now=NOW)

    source.bundle_doc = bundle(policy_key, version=2)
    report = dist.refresh(now=NOW + timedelta(minutes=1))

    assert report.alarming()
    assert not report.applied_bundle
    assert dist.snapshot.version == 5, "the old bundle must not have replaced the current one"


def test_a_bundle_for_another_fleet_is_refused(source, root, policy_key):
    """Staging is always the weakest environment."""
    dist = make(source, root)
    source.bundle_doc = bundle(policy_key, fleet="staging")
    report = dist.refresh(now=NOW)

    assert report.alarming()
    assert dist.snapshot.health is Health.UNPROVISIONED


def test_a_tampered_file_rejects_the_whole_bundle(source, root, policy_key):
    """All or nothing.

    A partially applied bundle is a policy nobody wrote and nobody reviewed —
    worse than keeping the previous one, which at least someone approved.
    """
    doc = bundle(policy_key, files={"a.yaml": b"deny: all", "b.yaml": b"allow: reads"})
    doc["files"]["b.yaml"] = "allow: everything"
    source.bundle_doc = doc

    dist = make(source, root)
    report = dist.refresh(now=NOW)

    assert report.alarming()
    assert dist.snapshot.files == {}


# --- containment --------------------------------------------------------------


def test_a_contained_agent_is_denied_regardless_of_policy(source, root, policy_key):
    """Containment overrides the rules, which is the point of a kill switch.

    If policy could allow past it, the button an operator pressed would do
    nothing whenever the rules happened to permit the action.
    """
    source.revocations_doc = revocations(
        policy_key, entries=[{"principal_id": AGENT, "mode": "deny", "allow": []}]
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    forced = dist.gate(action())
    assert forced.verdict == "deny"
    assert forced.source == "containment"
    assert dist.gate(action(principal="agent:other")) is None


def test_defer_mode_sends_everything_to_a_human(source, root, policy_key):
    source.revocations_doc = revocations(
        policy_key, entries=[{"principal_id": AGENT, "mode": "defer", "allow": []}]
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    assert dist.gate(action()).verdict == "defer"


def test_deny_except_lets_the_allowlist_through(source, root, policy_key):
    """An incident responder can look without letting the agent act."""
    source.revocations_doc = revocations(
        policy_key,
        entries=[
            {
                "principal_id": AGENT,
                "mode": "deny_except",
                "allow": ["mcp://filesystem/read_*"],
            }
        ],
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    assert dist.gate(action(tool="mcp://filesystem/read_file")) is None
    assert dist.gate(action(tool="sdk://payments/refund")).verdict == "deny"


def test_a_stale_revocation_list_escalates_rather_than_assuming_nobody_is_contained(source, root):
    """The asymmetry with policy, and the reason these are separate artifacts.

    Old rules are still rules. But a revocation list we cannot verify means we
    do not know whether an agent has been contained, and assuming it has not is
    precisely the fail-open a kill switch exists to prevent.
    """
    dist = make(source, root)
    dist.refresh(now=NOW)
    assert dist.gate(action()) is None

    source.down = True
    dist.refresh(now=NOW + timedelta(hours=1))

    assert dist.snapshot.health is Health.FRESH, "policy is still fresh"
    assert dist.snapshot.revocations_health is Health.STALE
    forced = dist.gate(action())
    assert forced is not None and forced.verdict == "defer"
    assert "contained" in (forced.reason or "")


def test_containment_still_applies_when_its_list_is_stale(source, root, policy_key):
    """A known containment must not be released by the list going stale.

    Otherwise waiting fifteen minutes releases every contained agent, which is
    a cheaper attack than forging anything.
    """
    source.revocations_doc = revocations(
        policy_key, entries=[{"principal_id": AGENT, "mode": "deny", "allow": []}]
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    source.down = True
    dist.refresh(now=NOW + timedelta(hours=1))

    forced = dist.gate(action())
    assert forced.verdict == "deny"
    assert forced.source == "containment"


# --- persistence --------------------------------------------------------------


def test_a_restart_does_not_become_an_outage(source, root, tmp_path):
    """Restarts happen during deploys and incidents.

    Losing all policy then is least acceptable — and, not coincidentally, when
    an attacker would choose to block a fetch.
    """
    first = make(source, root, cache_dir=tmp_path)
    first.cache_keyset(source.keyset_doc)
    first.refresh(now=NOW)
    assert first.snapshot.health is Health.FRESH

    source.down = True
    restarted = make(source, root, cache_dir=tmp_path, now=NOW + timedelta(minutes=1))

    assert restarted.snapshot.version == first.snapshot.version
    assert restarted.gate(action()) is None


def test_a_tampered_cache_is_not_trusted(source, root, tmp_path):
    """The cache is a file in the customer's environment.

    Reloading it without checking the signature would turn it into a way to
    install policy — a local write becomes a fleet-wide rule change.
    """
    first = make(source, root, cache_dir=tmp_path)
    first.cache_keyset(source.keyset_doc)
    first.refresh(now=NOW)

    cached = json.loads((tmp_path / "bundle.json").read_text())
    cached["manifest"]["payload"] = b64u(b'{"schema":"unified.policy-bundle/v1","version":99}')
    (tmp_path / "bundle.json").write_text(json.dumps(cached))

    restarted = make(source, root, cache_dir=tmp_path, now=NOW + timedelta(minutes=1))
    assert restarted.snapshot.health is Health.UNPROVISIONED
    assert restarted.gate(action()).verdict == "deny"


# --- the wiring ---------------------------------------------------------------


def test_the_enforcer_consults_distribution_before_policy(source, root, policy_key):
    """Wired, not merely available.

    This project has already shipped one security feature that was correct and
    unreachable. An unwired kill switch is worse than none: it is a button an
    operator believes they pressed.
    """
    from unified_enforce.enforcer import Enforcer
    from unified_enforce.policy import PolicyEngine

    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: allow-all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    source.revocations_doc = revocations(
        policy_key, entries=[{"principal_id": AGENT, "mode": "deny", "allow": []}]
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    enforcer = Enforcer(engine, distribution=dist)

    # Policy says allow; containment must win anyway.
    assert enforcer.enforce(action()).verdict == "deny"
    # And an uncontained principal is still decided by policy.
    assert enforcer.enforce(action(principal="agent:other")).verdict == "allow"


def test_a_restart_remembers_who_was_contained_even_if_the_list_has_expired(
    source, root, policy_key, tmp_path
):
    """A restart must not release a contained agent.

    The cached list is past its 15-minute expiry, so it is not *current* — the
    sidecar escalates on that separately. But discarding it outright would
    forget the containment entirely, downgrading a hard `deny` to a defer at
    precisely the moment it matters: a restart during an incident.

    Recovered for contents, marked stale, never treated as fresh.
    """
    source.revocations_doc = revocations(
        policy_key, entries=[{"principal_id": AGENT, "mode": "deny", "allow": []}]
    )
    first = make(source, root, cache_dir=tmp_path)
    first.cache_keyset(source.keyset_doc)
    first.refresh(now=NOW)

    source.down = True
    restarted = make(source, root, cache_dir=tmp_path, now=NOW + timedelta(hours=1))

    assert restarted.snapshot.revocations_health is Health.STALE
    forced = restarted.gate(action())
    assert forced.verdict == "deny"
    assert forced.source == "containment", "the containment survived the restart"


# --- shadow candidates ----------------------------------------------------------


def with_shadow(enforce_doc, shadow_doc, version):
    return {**enforce_doc, "shadow": {"version": version, **shadow_doc}}


def test_a_candidate_is_held_but_never_enforced(source, root, policy_key):
    """The invariant shadow mode exists to keep.

    A candidate is a proposal. If it could replace the enforcing bundle, shadow
    mode would be a way to ship unreviewed policy while believing you were
    measuring it.
    """
    enforced = bundle(policy_key, version=1, files={"base.yaml": b"deny: all\n"})
    proposed = bundle(policy_key, version=2, mode="shadow", files={"base.yaml": b"allow: all\n"})
    source.bundle_doc = with_shadow(enforced, proposed, 2)

    dist = make(source, root)
    report = dist.refresh(now=NOW)

    assert report.applied_bundle and report.applied_shadow
    assert dist.snapshot.version == 1, "the enforcing bundle is unchanged"
    assert dist.snapshot.files == {"base.yaml": b"deny: all\n"}
    assert dist.snapshot.shadow_version == 2
    assert dist.snapshot.shadow_files == {"base.yaml": b"allow: all\n"}


def test_a_bundle_in_the_shadow_slot_must_say_shadow_inside_its_signature(source, root, policy_key):
    """Otherwise the slot decides, and the slot is not signed.

    A signed *enforcing* bundle offered as a candidate would be evaluated as a
    proposal — or, read the other way, whoever controls the response chooses
    which of two signed bundles is treated as policy.
    """
    enforced = bundle(policy_key, version=1)
    mislabelled = bundle(policy_key, version=2, mode="enforce")
    source.bundle_doc = with_shadow(enforced, mislabelled, 2)

    dist = make(source, root)
    report = dist.refresh(now=NOW)

    assert not report.applied_shadow
    assert report.alarming()
    assert dist.snapshot.shadow_version is None


def test_a_forged_candidate_is_refused_like_any_other_bundle(source, root, policy_key):
    """A divergence report is what an operator reads before promoting.

    An attacker who could forge a candidate would choose what that report says.
    """
    enforced = bundle(policy_key, version=1)
    forged = bundle(Key(), version=2, mode="shadow")
    source.bundle_doc = with_shadow(enforced, forged, 2)

    dist = make(source, root)
    report = dist.refresh(now=NOW)

    assert not report.applied_shadow
    assert report.alarming()


def test_a_candidate_for_another_fleet_is_refused(source, root, policy_key):
    enforced = bundle(policy_key, version=1)
    other = bundle(policy_key, version=2, mode="shadow", fleet="staging")
    source.bundle_doc = with_shadow(enforced, other, 2)

    dist = make(source, root)
    dist.refresh(now=NOW)

    assert dist.snapshot.shadow_version is None


def test_a_withdrawn_candidate_is_dropped(source, root, policy_key):
    """Promoted or superseded, there is nothing left to measure.

    Continuing would report divergences against a question nobody is asking.
    """
    enforced = bundle(policy_key, version=1)
    proposed = bundle(policy_key, version=2, mode="shadow")
    source.bundle_doc = with_shadow(enforced, proposed, 2)

    dist = make(source, root)
    dist.refresh(now=NOW)
    assert dist.snapshot.shadow_version == 2

    source.bundle_doc = enforced  # no shadow field any more
    dist.refresh(now=NOW + timedelta(minutes=1))

    assert dist.snapshot.shadow_version is None
    assert dist.snapshot.shadow_files == {}


def test_a_replayed_candidate_is_refused_on_its_own_freshness_line(source, root, policy_key):
    """The property the separate line actually buys.

    With a shared baseline, a candidate at v6 is compared against the enforcing
    v5 and a replayed v6 carrying an *earlier* expiry passes on `6 > 5` before
    the equal-version refresh rule is reached. An attacker could then pin the
    divergence report to a stale proposal — and that report is what an operator
    reads before promoting.
    """
    fresh = bundle(policy_key, version=2, mode="shadow", ttl=DAY)
    source.bundle_doc = with_shadow(bundle(policy_key, version=1), fresh, 2)

    dist = make(source, root)
    dist.refresh(now=NOW)
    assert dist.snapshot.shadow_version == 2

    stale = bundle(policy_key, version=2, mode="shadow", ttl=timedelta(hours=1))
    source.bundle_doc = with_shadow(bundle(policy_key, version=1), stale, 2)
    report = dist.refresh(now=NOW + timedelta(minutes=1))

    assert not report.applied_shadow, "a replayed candidate was accepted"
    assert report.alarming()


def test_a_candidate_does_not_block_the_enforcing_bundle_reaching_its_version(
    source, root, policy_key
):
    """Proposing a change must not stand in the way of shipping it.

    Versions are one sequence across both modes, so proposing v2 and then
    shipping v2 is the ordinary promotion path.
    """
    source.bundle_doc = with_shadow(
        bundle(policy_key, version=1), bundle(policy_key, version=2, mode="shadow"), 2
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    # The candidate is promoted: same version, now enforcing.
    source.bundle_doc = bundle(policy_key, version=2, now=NOW + timedelta(minutes=1))
    report = dist.refresh(now=NOW + timedelta(minutes=1))

    assert report.applied_bundle, f"promotion refused: {report.problems}"
    assert dist.snapshot.version == 2
    assert dist.snapshot.shadow_version is None


def test_a_replayed_revocation_list_is_refused(source, root, policy_key):
    """Same freshness rule, on the artifact where staleness matters most.

    A replayed refresh at the same version pushes the sidecar's idea of when
    the list expires *backwards*. Here that fails safe — an earlier expiry
    escalates sooner — but relying on a fail-safe accident for the containment
    artifact is not a control, and the same defect on the policy line would not
    fail safe at all.
    """
    source.revocations_doc = revocations(policy_key, version=1, ttl=timedelta(hours=1))
    dist = make(source, root)
    dist.refresh(now=NOW)
    assert dist.snapshot.revocations_version == 1

    source.revocations_doc = revocations(policy_key, version=1, ttl=timedelta(minutes=5))
    report = dist.refresh(now=NOW + timedelta(minutes=1))

    assert not report.applied_revocations, "a replayed revocation list was accepted"
    assert report.alarming()


# --- keys shared with the approval channel -------------------------------------


def test_verified_keys_are_published_for_other_verifiers(source, root, policy_key):
    """The approval channel checks signatures against these.

    `RemoteApprovals(..., keys=distribution.verification_keys)` is the intended
    wiring, so that rotating the decision key is a signed message rather than a
    fleet-wide re-enrolment. Pinning a key of its own at enrolment would be a
    second thing to rotate, which in practice means one that never is.
    """
    dist = make(source, root)
    assert dist.verification_keys() == {}, "nothing is trusted before a key set verifies"

    dist.refresh(now=NOW)

    assert policy_key.kid in dist.verification_keys()


def test_a_key_set_that_stops_verifying_drops_the_keys_it_authorised(source, root, policy_key):
    """Approvals must stop being honoured, not keep being honoured on stale authority.

    This is the quiet failure the whole key hierarchy exists to avoid. Keeping
    the previous keys after a key set expires or fails to verify means a sidecar
    goes on accepting signed decisions using authority that is no longer
    vouched for — including, after a compromise, decisions signed by a key that
    was supposed to have been rotated out. The visible consequence of dropping
    them is that deferred actions deny, which is the correct direction.
    """
    dist = make(source, root)
    dist.refresh(now=NOW)
    assert dist.verification_keys()

    # Same document, read far enough in the future that it has expired.
    report = dist.refresh(now=NOW + 30 * DAY)

    assert report.alarming
    assert dist.verification_keys() == {}, (
        "a sidecar would keep honouring decisions on an expired key set"
    )


def test_an_unreachable_source_keeps_the_keys_it_already_trusts(source, root, policy_key):
    """Brief unreachability is ordinary and must not disarm approvals.

    The distinction from the test above is the whole point: a key set that
    *failed to verify* is evidence something is wrong, while a source that
    cannot be reached is evidence of nothing. Dropping keys on the second would
    turn every network blip into an approval outage, and an outage that
    ordinary conditions cause is one people route around.
    """
    dist = make(source, root)
    dist.refresh(now=NOW)

    source.down = True
    report = dist.refresh(now=NOW + timedelta(minutes=1))

    assert report.unreachable
    assert policy_key.kid in dist.verification_keys()


# --- the whole fleet -----------------------------------------------------------------


def test_containing_the_fleet_contains_an_agent_never_named(source, root, policy_key):
    """The button pressed when nobody knows yet which agent is the problem.

    A per-principal list cannot express that: an incident responder would have
    to enumerate agents they may not know about, and the one they miss is the
    one that matters.
    """
    source.revocations_doc = revocations(
        policy_key, version=2, entries=[{"principal_id": "*", "mode": "deny", "reason": "incident"}]
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    forced = dist.gate(action(principal="agent:never-heard-of"))

    assert forced is not None
    assert forced.verdict is Verdict.DENY


def test_a_narrower_rule_cannot_weaken_a_fleet_wide_stop(source, root, policy_key):
    """Composition takes the strictest, and this is why.

    A fleet-wide `deny` softened to `defer` by a per-principal entry somebody
    set last week is not a kill switch — and that entry is invisible to whoever
    is pressing the button.
    """
    source.revocations_doc = revocations(
        policy_key,
        version=2,
        entries=[
            {"principal_id": "*", "mode": "deny", "reason": "incident"},
            {"principal_id": AGENT, "mode": "defer", "reason": "watch this one"},
        ],
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    forced = dist.gate(action(principal=AGENT))

    assert forced.verdict is Verdict.DENY, "a stale per-principal rule weakened the kill switch"


def test_a_narrower_rule_can_still_tighten(source, root, policy_key):
    """The other direction is fine: containing the fleet to `defer` while one
    known-bad agent is denied outright is exactly what an incident looks like
    halfway through."""
    source.revocations_doc = revocations(
        policy_key,
        version=2,
        entries=[
            {"principal_id": "*", "mode": "defer", "reason": "incident"},
            {"principal_id": AGENT, "mode": "deny", "reason": "confirmed"},
        ],
    )
    dist = make(source, root)
    dist.refresh(now=NOW)

    assert dist.gate(action(principal=AGENT)).verdict is Verdict.DENY
    assert dist.gate(action(principal="agent:other")).verdict is Verdict.DEFER


def test_an_uncontained_fleet_is_unaffected(source, root):
    """Pinned, so the wildcard cannot quietly start matching everything."""
    dist = make(source, root)
    dist.refresh(now=NOW)

    assert dist.gate(action(principal="agent:anyone")) is None


# --- fetching it over HTTP, and continuing to ---------------------------------


def _serve(handlers: dict[str, object]):
    """A control plane that answers the three artifact routes and counts hits."""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    hits: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 — http.server's interface
            hits.append(self.path)
            body = handlers.get(self.path)
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            if isinstance(body, int):
                self.send_response(body)
                self.end_headers()
                return
            raw = _json.dumps(body).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}", hits


def test_the_http_source_reads_what_the_control_plane_serves(root, policy_key):
    """Including the shape the revocations route actually returns.

    That route wraps the signed envelope alongside a version — `{"version": 1,
    "revocations": {...}}` — and `_apply_revocations` unwraps it. An earlier
    version of this source unwrapped it *too*, so every list arrived as `None`
    and was refused as malformed. Because an unusable revocation list escalates
    rather than assuming nobody is contained, the symptom was a fleet denying
    everything, which reads as a policy problem and not as a fetch that is
    double-peeling one layer of JSON. Found by pointing this at a running
    service; no unit test with a hand-built source would have.
    """
    server, base, _ = _serve(
        {
            "/api/v1/policy/keyset": keyset(root, policy_key),
            "/api/v1/policy/bundle": bundle(policy_key),
            # The helper already produces the route's wrapper shape.
            "/api/v1/policy/revocations": revocations(policy_key),
        }
    )
    try:
        dist = Distribution(
            ControlPlaneSource(base, "cred"), fleet_id=FLEET, root_public_key=root.public
        )
        report = dist.refresh(now=NOW)
    finally:
        server.shutdown()

    assert not report.problems, report.problems
    assert dist.snapshot.is_usable()
    assert dist.gate(action()) is None


def test_the_http_source_sends_the_credential_and_the_channel_binding(root, policy_key):
    """A stolen bearer token alone should not read another fleet's policy."""
    captured: list[tuple[str, str]] = []

    class Channel:
        def headers(self, method, path, body):
            captured.append((method, path))
            return {"x-unified-proof": "signed"}

    server, base, _ = _serve({"/api/v1/policy/keyset": keyset(root, policy_key)})
    try:
        ControlPlaneSource(base, "cred", channel=Channel()).fetch_keyset()
    finally:
        server.shutdown()

    assert captured == [("GET", "/api/v1/policy/keyset")]


def test_an_unreachable_control_plane_is_a_refusal_the_poll_can_handle(root):
    """`SourceUnavailable`, not an escaping `URLError` — `refresh()` promises
    never to raise, and it can only keep that promise if the source is
    predictable about how it fails."""
    from unified_enforce.distribution import SourceUnavailable

    server, base, _ = _serve({})
    server.shutdown()
    server.server_close()  # or the port stays open and the fetch hangs instead

    with pytest.raises(SourceUnavailable):
        ControlPlaneSource(base, "cred", http_timeout=1.0).fetch_keyset()


async def test_the_poller_keeps_polling_after_a_refresh_raises(source, root):
    """The failure this class exists to not have.

    A poller that dies on one exception leaves a sidecar gating perfectly
    against a snapshot from Tuesday, with every health check green, and
    containment ordered afterwards never arriving. So the loop swallows, and
    this test makes the first refresh explode to prove the second still runs.
    """
    import asyncio

    dist = make(source, root)
    calls = {"n": 0}
    real = dist.refresh

    def exploding(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("a refresh that should not have raised")
        return real(*args, **kwargs)

    dist.refresh = exploding  # type: ignore[method-assign]
    poller = Poller(dist, interval_seconds=0.01)
    await poller.start()
    try:
        for _ in range(200):
            await asyncio.sleep(0.01)
            if calls["n"] >= 3:
                break
    finally:
        await poller.stop()

    assert calls["n"] >= 3, "the poller stopped at the first exception"


async def test_containment_lands_within_one_poll(root, policy_key):
    """The bound, measured rather than asserted, against a source that changes
    underneath a running poller — the same thing the live measurement does, in
    a form CI can run."""
    import asyncio
    import time

    # Real clock, because the poller uses one: artifacts stamped at the
    # module's fixed NOW are expired by the time anyone runs this.
    live = datetime.now(UTC)
    source = FakeSource(
        keyset(root, policy_key, now=live),
        bundle(policy_key, now=live),
        revocations(policy_key, now=live),
    )
    dist = make(source, root)
    poller = Poller(dist, interval_seconds=0.05)
    await poller.start()
    try:
        for _ in range(100):
            await asyncio.sleep(0.01)
            if dist.snapshot.is_usable():
                break
        assert dist.gate(action()) is None, "gated before anything was contained"

        source.revocations_doc = revocations(
            policy_key, version=2, entries=[{"principal_id": AGENT, "mode": "deny"}], now=live
        )
        pressed = time.monotonic()
        for _ in range(200):
            decision = dist.gate(action())
            if decision is not None and decision.verdict is Verdict.DENY:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("containment never took effect")
    finally:
        await poller.stop()

    assert time.monotonic() - pressed < 1.0


# --- receipts: refresh at once when the list moved --------------------------------
#
# The evidence receipt for the batch that raised an incident carries the fleet's
# revocation-list version. The reporting sidecar is the one running the agent
# that was just contained, and the one that would otherwise wait up to a full
# poll interval to hear about it. These hold the property, and its limit: the
# receipt is a cue, never a source.


def test_a_moved_revocations_version_refreshes_at_once(source, root, policy_key):
    dist = make(source, root)
    dist.refresh(now=NOW)
    assert dist.snapshot.revocations_version == 1
    assert dist.gate(action()) is None

    # The control plane contained this agent (Active mode: defer) and said so
    # in the receipt for the batch that caused it.
    source.revocations_doc = revocations(
        policy_key, version=2, entries=[{"principal_id": AGENT, "mode": "defer", "allow": []}]
    )
    report = dist.on_receipt({"accepted": 1, "raised": 1, "revocations_version": 2}, now=NOW)

    assert report is not None, "a moved version must trigger a refresh"
    assert dist.snapshot.revocations_version == 2
    forced = dist.gate(action())
    assert forced is not None and forced.verdict == "defer"


def test_an_unmoved_version_does_not_refresh(source, root):
    dist = make(source, root)
    dist.refresh(now=NOW)

    fetches = 0
    original = source.fetch_revocations

    def counting():
        nonlocal fetches
        fetches += 1
        return original()

    source.fetch_revocations = counting

    assert dist.on_receipt({"revocations_version": 1}, now=NOW) is None
    assert dist.on_receipt({"revocations_version": 0}, now=NOW) is None
    assert dist.on_receipt({"revocations_version": None}, now=NOW) is None
    assert dist.on_receipt({"revocations_version": "2"}, now=NOW) is None
    assert dist.on_receipt({}, now=NOW) is None
    assert fetches == 0


def test_a_forged_receipt_cannot_downgrade_contain_or_release(source, root, policy_key):
    """THE NEGATIVE CONTROL for receipts. Anyone who can answer an evidence
    post can write a receipt. It may cost one verified fetch and nothing else:
    the refresh it triggers still checks every signature against the pinned
    root and still refuses a version older than the one held."""
    contained = [{"principal_id": AGENT, "mode": "deny", "allow": []}]
    source.revocations_doc = revocations(policy_key, version=3, entries=contained)
    dist = make(source, root)
    dist.refresh(now=NOW)
    assert dist.gate(action()).verdict == "deny"

    # A receipt claiming a far newer version. The source still serves 3, so a
    # refresh changes nothing — and the agent stays contained.
    dist.on_receipt({"revocations_version": 99}, now=NOW)
    assert dist.snapshot.revocations_version == 3
    assert dist.gate(action()).verdict == "deny"

    # A receipt cannot carry the list itself. Only the signed fetch counts.
    dist.on_receipt({"revocations_version": 100, "revocations": []}, now=NOW)
    assert dist.gate(action()).verdict == "deny"

    # And a receipt cannot release: an older version in the receipt is ignored,
    # and an older version *served* is refused as the rollback it is.
    source.revocations_doc = revocations(policy_key, version=1, entries=[])
    dist.on_receipt({"revocations_version": 4}, now=NOW)
    assert dist.snapshot.revocations_version == 3
    assert dist.gate(action()).verdict == "deny"


def test_the_enforcer_wires_the_receipt_to_distribution(source, root):
    """Wired, not merely available — the same rule as the kill switch."""
    from unified_enforce.enforcer import Enforcer
    from unified_enforce.evidence import EvidenceShipper
    from unified_enforce.policy import PolicyEngine

    class Quiet:
        def send(self, batch):
            return None

    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: allow-all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    dist = make(source, root)
    shipper = EvidenceShipper(Quiet())
    assert shipper.on_receipt is None

    Enforcer(engine, distribution=dist, evidence=shipper)

    assert shipper.on_receipt == dist.on_receipt

    # A deployment that wired its own handler keeps it.
    mine = lambda receipt: None  # noqa: E731
    other = EvidenceShipper(Quiet(), on_receipt=mine)
    Enforcer(engine, distribution=dist, evidence=other)
    assert other.on_receipt is mine


# --- containment announcements (build-04: the enforcement point that can stop
# --- a call in progress needs to hear that the list changed) ------------------


def test_a_containment_change_is_announced(source, root, policy_key):
    heard: list[tuple[frozenset, frozenset]] = []
    dist = make(source, root, on_containment=lambda a, r: heard.append((a, r)))
    dist.refresh(now=NOW)
    assert heard == [], "an empty list contains nobody; nothing to announce"

    source.revocations_doc = revocations(
        policy_key, version=2, entries=[{"principal_id": AGENT, "mode": "defer", "allow": []}]
    )
    dist.refresh(now=NOW)
    assert heard == [(frozenset({AGENT}), frozenset())]

    # Tightened, not merely re-listed: still news to a call in flight.
    source.revocations_doc = revocations(
        policy_key, version=3, entries=[{"principal_id": AGENT, "mode": "deny", "allow": []}]
    )
    dist.refresh(now=NOW)
    assert heard[-1] == (frozenset({AGENT}), frozenset())

    source.revocations_doc = revocations(policy_key, version=4, entries=[])
    dist.refresh(now=NOW)
    assert heard[-1] == (frozenset(), frozenset({AGENT}))


def test_an_unchanged_list_announces_nothing(source, root, policy_key):
    heard: list = []
    source.revocations_doc = revocations(
        policy_key, version=2, entries=[{"principal_id": AGENT, "mode": "defer", "allow": []}]
    )
    dist = make(source, root, on_containment=lambda a, r: heard.append((a, r)))
    dist.refresh(now=NOW)
    assert len(heard) == 1
    # Same entries, new version: the list was reissued, nobody's state moved.
    source.revocations_doc = revocations(
        policy_key, version=3, entries=[{"principal_id": AGENT, "mode": "defer", "allow": []}]
    )
    dist.refresh(now=NOW)
    assert len(heard) == 1


def test_hydration_from_cache_announces_nothing(source, root, policy_key, tmp_path):
    source.revocations_doc = revocations(
        policy_key, version=2, entries=[{"principal_id": AGENT, "mode": "deny", "allow": []}]
    )
    first = make(source, root, cache_dir=tmp_path)
    first.cache_keyset(source.keyset_doc)
    first.refresh(now=NOW)

    heard: list = []
    second = make(
        source,
        root,
        cache_dir=tmp_path,
        on_containment=lambda a, r: heard.append((a, r)),
        now=NOW,
    )
    assert AGENT in second.snapshot.containment, "the cache restored containment"
    assert heard == [], "nothing is in flight at start-up; hydration is not a change"


def test_a_failing_containment_handler_never_fails_the_refresh(source, root, policy_key):
    def explode(added, removed):
        raise RuntimeError("handler bug")

    dist = make(source, root, on_containment=explode)
    dist.refresh(now=NOW)
    source.revocations_doc = revocations(
        policy_key, version=2, entries=[{"principal_id": AGENT, "mode": "deny", "allow": []}]
    )
    report = dist.refresh(now=NOW)
    assert report.applied_revocations
    assert not [p for p in report.problems if p[0] == "revocations"]
    forced = dist.gate(action())
    assert forced is not None and forced.verdict == Verdict.DENY, (
        "the list is applied before it is announced; a broken handler cannot un-contain"
    )
