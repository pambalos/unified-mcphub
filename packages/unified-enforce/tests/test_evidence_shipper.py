"""Shipping evidence must never cost a decision, and must never lie about loss.

Two failure modes are being defended against, and they pull in opposite
directions.

The first is *evidence becoming load-bearing*: a control plane that is slow,
down or hostile silently degrading enforcement. Everything here that asserts
"the verdict is unchanged" is guarding that.

The second is *silent loss*: a dashboard built on evidence that quietly went
missing, which is worse than one admitting a gap because the first is believed.
Everything here that asserts on `dropped`, `chain_seq` and requeueing is
guarding that.
"""

from __future__ import annotations

import threading
import time

import pytest

from unified_enforce import Action, Principal
from unified_enforce.evidence import EvidenceShipper, EvidenceSpool, summarise
from unified_enforce.policy import Decision


def action(**overrides) -> Action:
    kwargs = dict(
        principal=Principal(id="agent:payments-1"),
        tool="sdk://payments/refund",
        verb="create",
        resource="table:billing.invoices",
        params={"amount": "12400.00", "customer": "cus_8812", "iban": "GB33BUKB20201555555555"},
    )
    kwargs.update(overrides)
    return Action.build(**kwargs)


def decision(verdict="deny") -> Decision:
    return Decision(verdict=verdict, rule_id="floor.payouts", source="floor")


class Collecting:
    def __init__(self) -> None:
        self.batches: list[list[dict]] = []

    def send(self, batch):
        self.batches.append(list(batch))

    @property
    def records(self) -> list[dict]:
        return [r for batch in self.batches for r in batch]


class Broken:
    def __init__(self, error=ConnectionError("control plane unreachable")) -> None:
        self.error = error
        self.attempts = 0

    def send(self, batch):
        self.attempts += 1
        raise self.error


class Hanging:
    def __init__(self) -> None:
        self.released = threading.Event()

    def send(self, batch):
        self.released.wait(timeout=30)


# --- content never leaves ------------------------------------------------------


def test_no_action_content_is_ever_shipped():
    """Enforced here, not delegated to the receiver.

    The control plane rejects `params`, and should. But a sidecar that sends
    content and is refused has still put it on a wire and possibly into a log
    at the far end. The promise is that it never leaves.
    """
    record = summarise(action(), decision())

    flat = repr(record)
    assert "12400.00" not in flat
    assert "cus_8812" not in flat
    assert "GB33BUKB" not in flat
    assert "params" not in record


def test_the_payload_is_an_allowlist():
    """A denylist would ship whatever gets added to `Action` next.

    And the field most likely to be added is another one carrying content.

    Equality rather than a subset, so adding a field is a deliberate edit here
    with a reason attached. `attestation` and `parent_id` were added that way:
    both describe *how the identity was arrived at* rather than what the agent
    did, which is the line this list draws. Neither can carry payload — one is
    a three-value enum, the other a principal id that already ships above it.
    """
    assert set(summarise(action(), decision())) == {
        "action_digest",
        "principal_id",
        "tool",
        "verb",
        "resource",
        "verdict",
        "rule_id",
        "source",
        "chain_seq",
        "chain_hash",
        "attestation",
        "parent_id",
        "decided_at",
    }


def test_the_digest_travels_so_a_record_can_be_corroborated():
    """The metadata is only useful because it points at the real evidence."""
    a = action()
    assert summarise(a, decision())["action_digest"] == a.digest()


# --- never in the decision path ------------------------------------------------


def test_recording_cannot_raise_even_when_summarising_fails():
    """A defect here must not become a failed enforcement.

    By the time this is called the engine has decided and the chain is written.
    Nothing in a telemetry copy is worth losing that over.
    """
    shipper = EvidenceShipper(Collecting())

    class Exploding:
        digest = property(lambda self: 1 / 0)

    shipper.record(Exploding(), decision())  # must not raise


def test_a_broken_sink_does_not_reach_the_caller():
    shipper = EvidenceShipper(Broken())
    shipper.record(action(), decision())

    assert shipper.flush() == 0
    assert shipper.spool.stats.failures == 1


def test_recording_does_not_wait_on_the_network():
    """`record()` queues and returns.

    If it shipped inline, an unreachable control plane would add its timeout to
    every agent action — turning our outage into their latency.
    """
    hanging = Hanging()
    shipper = EvidenceShipper(hanging, batch_size=1)

    started = time.monotonic()
    for _ in range(50):
        shipper.record(action(), decision())
    elapsed = time.monotonic() - started

    assert elapsed < 0.5, f"recording blocked for {elapsed:.2f}s"
    hanging.released.set()


def test_the_enforcer_returns_the_same_verdict_with_a_broken_control_plane():
    """The property the whole module exists for."""
    from unified_enforce.enforcer import Enforcer
    from unified_enforce.policy import PolicyEngine

    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: deny-payouts\n    match:\n      tool: '**'\n    effect: deny\n"
    )
    without = Enforcer(engine).enforce(action())
    with_broken = Enforcer(engine, evidence=EvidenceShipper(Broken())).enforce(action())

    assert without.verdict == with_broken.verdict


# --- loss is bounded, counted, and visible ------------------------------------


def test_the_spool_is_bounded():
    """A control plane that stops accepting must not grow a sidecar until
    something else on the host dies."""
    spool = EvidenceSpool(capacity=10)
    for i in range(100):
        spool.add({"n": i})

    assert len(spool) == 10
    assert spool.stats.dropped == 90


def test_the_oldest_records_are_dropped_not_the_newest():
    """The documented policy, asserted rather than assumed.

    During an outage the recent decisions are the ones an operator is about to
    ask about, and `chain_seq` makes the resulting hole visible to the receiver.
    """
    spool = EvidenceSpool(capacity=3)
    for i in range(6):
        spool.add({"n": i})

    assert [r["n"] for r in spool.take(10)] == [3, 4, 5]


def test_a_failed_send_requeues_rather_than_dropping():
    """Otherwise an unreachable control plane is indistinguishable from a quiet
    agent, which is the confusion this module exists to avoid."""
    broken = Broken()
    shipper = EvidenceShipper(broken)
    for _ in range(5):
        shipper.record(action(), decision())

    shipper.flush()

    assert len(shipper.spool) == 5, "records lost to a send failure"
    assert shipper.spool.stats.dropped == 0


def test_records_survive_an_outage_and_ship_on_reconnect():
    """The backfill, end to end."""
    sink = Collecting()
    broken = Broken()
    shipper = EvidenceShipper(broken, batch_size=2)

    for _ in range(5):
        shipper.record(action(), decision())
    shipper.flush()
    assert broken.attempts == 1

    shipper._sink = sink  # reconnected
    assert shipper.flush() == 5
    assert len(sink.records) == 5


def test_requeued_records_keep_their_order():
    """A receiver reasons about `chain_seq` ranges; shuffling them on retry
    turns a clean gap into a puzzle."""
    broken = Broken()
    shipper = EvidenceShipper(broken, batch_size=2)
    for i in range(4):
        shipper.spool.add({"n": i})

    shipper.flush()

    assert [r["n"] for r in shipper.spool.take(10)] == [0, 1, 2, 3]


def test_dropping_is_counted_so_a_gap_is_never_silent():
    """`dropped` is the difference between a dashboard with a known gap and one
    that is quietly wrong. The second is believed."""
    shipper = EvidenceShipper(Broken(), capacity=3)
    for _ in range(10):
        shipper.record(action(), decision())

    assert shipper.spool.stats.dropped == 7
    assert len(shipper.spool) == 3


# --- chain correspondence ------------------------------------------------------


def test_the_chain_position_ships_with_the_record(tmp_path):
    """So a receiver can see a missing range rather than infer a quiet agent."""
    from unified_enforce.audit import AuditChain
    from unified_enforce.enforcer import Enforcer
    from unified_enforce.policy import PolicyEngine

    chain = AuditChain(tmp_path)
    chain.start()
    sink = Collecting()
    shipper = EvidenceShipper(sink)
    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    enforcer = Enforcer(engine, chain=chain, evidence=shipper)

    for _ in range(3):
        enforcer.enforce(action())
    shipper.flush()
    chain.stop()

    seqs = [r["chain_seq"] for r in sink.records]
    assert seqs == [1, 2, 3]
    assert all(r["chain_hash"] for r in sink.records)


def test_a_decision_whose_chain_write_failed_is_not_shipped(tmp_path):
    """The dashboard is a copy, not the record.

    Reporting a decision the chain does not hold would put a row in front of an
    operator that cannot be corroborated against the evidence it claims to
    summarise — and corroboration is the entire reason the digest travels.
    """
    from unified_enforce.enforcer import Enforcer
    from unified_enforce.policy import PolicyEngine

    class FailingChain:
        def append_decision(self, action, decision, **_):
            raise OSError("disk full")

    sink = Collecting()
    shipper = EvidenceShipper(sink)
    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    enforcer = Enforcer(engine, chain=FailingChain(), evidence=shipper)

    with pytest.raises(OSError):
        enforcer.enforce(action())

    shipper.flush()
    assert sink.records == []


# --- lifecycle -----------------------------------------------------------------


def test_the_background_thread_ships_without_being_asked():
    sink = Collecting()
    shipper = EvidenceShipper(sink, interval_seconds=0.05)
    shipper.start()
    try:
        shipper.record(action(), decision())
        deadline = time.monotonic() + 3
        while not sink.records and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        shipper.stop(timeout=1)

    assert len(sink.records) == 1


def test_a_flush_that_raises_does_not_kill_the_thread():
    """Otherwise evidence stops for the life of the process and nothing says so."""

    class SometimesBroken:
        def __init__(self):
            self.calls = 0
            self.batches = []

        def send(self, batch):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient")
            self.batches.append(list(batch))

    sink = SometimesBroken()
    shipper = EvidenceShipper(sink, interval_seconds=0.05)
    shipper.start()
    try:
        shipper.record(action(), decision())
        deadline = time.monotonic() + 3
        while not sink.batches and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        shipper.stop(timeout=1)

    assert sink.batches, "the shipper stopped after one failure"


def test_stopping_does_not_hang_on_an_unreachable_control_plane():
    """A shutdown that waits on a dead receiver is a worse failure than losing
    the tail of a spool — which is in the chain regardless."""
    hanging = Hanging()
    shipper = EvidenceShipper(hanging, interval_seconds=0.05)
    shipper.start()
    shipper.record(action(), decision())

    started = time.monotonic()
    stopper = threading.Thread(target=lambda: shipper.stop(timeout=0.2))
    stopper.start()
    stopper.join(timeout=5)
    hanging.released.set()

    assert not stopper.is_alive(), "stop() hung"
    assert time.monotonic() - started < 5


# --- over a real socket --------------------------------------------------------


class Receiver:
    """A control-plane stand-in on a real port.

    Over HTTP rather than a mock, because the failures that matter here are
    protocol-shaped: a status code read the wrong way round, a header the server
    does not see, a timeout that is not applied. None of those show up against
    an object with a `send` method.
    """

    def __init__(self, status=202, delay=0.0, body=b"{}"):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        self.batches: list[list[dict]] = []
        self.auth: list[str | None] = []
        self.status = status
        self.delay = delay
        #: What the receiver answers with. The control plane answers a receipt.
        self.body = body
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                import json as _json

                length = int(self.headers.get("content-length", 0))
                body = _json.loads(self.rfile.read(length) or b"{}")
                receiver.auth.append(self.headers.get("authorization"))
                if receiver.delay:
                    time.sleep(receiver.delay)
                if receiver.status < 300:
                    receiver.batches.append(body.get("decisions", []))
                self.send_response(receiver.status)
                self.end_headers()
                self.wfile.write(receiver.body)

            def log_message(self, *args):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    @property
    def records(self):
        return [r for b in self.batches for r in b]


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


def test_records_reach_a_real_endpoint_with_the_credential(receiver):
    from unified_enforce.evidence import HttpSink

    shipper = EvidenceShipper(HttpSink(receiver.url, "uai_sc_test-credential"))
    # Captured once: every `action()` mints a fresh ULID and timestamp, and the
    # digest covers both, so comparing against a second call compares two
    # different actions.
    shipped = action()
    shipper.record(shipped, decision())

    assert shipper.flush() == 1
    assert len(receiver.records) == 1
    assert receiver.auth == ["Bearer uai_sc_test-credential"]

    record = receiver.records[0]
    assert record["action_digest"] == shipped.digest()
    assert "params" not in record


def test_a_server_error_requeues():
    """5xx is the receiver's problem. The records wait."""
    from unified_enforce.evidence import HttpSink

    server = Receiver(status=500)
    try:
        shipper = EvidenceShipper(HttpSink(server.url, "t"))
        shipper.record(action(), decision())
        shipper.flush()
        assert len(shipper.spool) == 1
        assert shipper.spool.stats.rejected == 0
    finally:
        server.close()


@pytest.mark.parametrize("status", [400, 410, 422])
def test_a_permanent_refusal_discards_rather_than_blocking_the_queue(status):
    """One poison batch must not stop all evidence for the life of the process.

    Requeueing a batch the receiver refuses on its merits parks it at the head
    of the queue forever; every later record piles up behind it and the spool
    fills and starts dropping, with the cause sitting at the front unlogged.
    """
    from unified_enforce.evidence import HttpSink

    server = Receiver(status=status)
    try:
        shipper = EvidenceShipper(HttpSink(server.url, "t"), batch_size=1)
        shipper.record(action(), decision())
        shipper.record(action(tool="sdk://payments/lookup"), decision("allow"))

        shipper.flush()

        assert len(shipper.spool) == 0, "a permanent refusal blocked the queue"
        assert shipper.spool.stats.rejected == 2
    finally:
        server.close()


def test_rate_limiting_is_transient_not_permanent():
    """429 is explicitly "try later" — discarding on it would lose evidence for
    the one reason the receiver has told us not to."""
    from unified_enforce.evidence import HttpSink

    server = Receiver(status=429)
    try:
        shipper = EvidenceShipper(HttpSink(server.url, "t"))
        shipper.record(action(), decision())
        shipper.flush()

        assert len(shipper.spool) == 1
        assert shipper.spool.stats.rejected == 0
    finally:
        server.close()


def test_a_slow_receiver_cannot_stall_shipping_forever():
    """The timeout is applied.

    A stuck socket cannot delay a decision — shipping is on another thread —
    but it can stall shipping indefinitely, turning a slow receiver into
    staleness nobody notices.
    """
    from unified_enforce.evidence import HttpSink

    server = Receiver(delay=5)
    try:
        shipper = EvidenceShipper(HttpSink(server.url, "t", timeout_seconds=0.3))
        shipper.record(action(), decision())

        started = time.monotonic()
        shipper.flush()
        elapsed = time.monotonic() - started

        assert elapsed < 3, f"flush waited {elapsed:.1f}s despite a 0.3s timeout"
        assert len(shipper.spool) == 1, "the record should be requeued, not lost"
    finally:
        server.close()


# --- receipts: the receiver answers, and the sidecar may act on it --------------


class Receipting(Collecting):
    """A sink that answers the way the control plane does."""

    def __init__(self, receipt):
        super().__init__()
        self.receipt = receipt

    def send(self, batch):
        super().send(batch)
        return self.receipt


def test_the_receipt_reaches_the_callback():
    seen: list[dict] = []
    shipper = EvidenceShipper(
        Receipting({"accepted": 1, "raised": 1, "revocations_version": 4}),
        on_receipt=seen.append,
    )
    shipper.record(action(), decision())

    assert shipper.flush() == 1
    assert seen == [{"accepted": 1, "raised": 1, "revocations_version": 4}]


def test_a_sink_without_receipts_is_still_fine():
    """Every sink written before receipts existed returns None."""
    seen: list[dict] = []
    shipper = EvidenceShipper(Collecting(), on_receipt=seen.append)
    shipper.record(action(), decision())

    assert shipper.flush() == 1
    assert seen == []


def test_a_receipt_handler_failure_never_fails_shipping():
    """The records are already accepted. A refresh that blows up must not look
    like a send failure, or the batch would be requeued and shipped twice."""

    def explode(receipt):
        raise RuntimeError("refresh exploded")

    sink = Receipting({"revocations_version": 2})
    shipper = EvidenceShipper(sink, on_receipt=explode)
    shipper.record(action(), decision())

    assert shipper.flush() == 1
    assert len(sink.records) == 1
    assert shipper.spool.stats.failures == 0
    assert len(shipper.spool) == 0


def test_an_http_receipt_is_parsed_and_handed_on():
    from unified_enforce.evidence import HttpSink

    server = Receiver(body=b'{"accepted": 1, "raised": 1, "revocations_version": 7}')
    try:
        seen: list[dict] = []
        shipper = EvidenceShipper(HttpSink(server.url, "t"), on_receipt=seen.append)
        shipper.record(action(), decision())

        assert shipper.flush() == 1
        assert seen == [{"accepted": 1, "raised": 1, "revocations_version": 7}]
    finally:
        server.close()


def test_an_unparseable_receipt_is_accepted_and_ignored():
    """202 is accepted whatever the body says. A receiver that answered
    nonsense has still taken the records; resending them would be wrong."""
    from unified_enforce.evidence import HttpSink

    server = Receiver(body=b"not json")
    try:
        seen: list[dict] = []
        shipper = EvidenceShipper(HttpSink(server.url, "t"), on_receipt=seen.append)
        shipper.record(action(), decision())

        assert shipper.flush() == 1
        assert seen == []
        assert len(server.records) == 1
        assert len(shipper.spool) == 0
    finally:
        server.close()
