"""The payload stream: content leaves only when asked for, and only as recorded.

payload-evidence.v1 lets a control plane hold copies of arguments and results.
That is the one thing in this package that puts customer content on a wire, so
the property under test is mostly *when it does not*:

- before the control plane has said it accepts, nothing is sent;
- once it says it refuses (or says nothing about payloads), nothing is sent,
  and what was held is discarded;
- a value larger than it will take is not sent;
- without a signer nothing is sent (the receiver refuses unsigned payloads);
- a value the chain did not record is not sent -- there is nothing to send;
- and none of it can touch a decision or decision evidence.

When something *is* sent, it must verify with `attest.accept_payload_evidence`
-- the canonical check the control plane runs -- against the chain entry it
names. A record that would be refused is worse than none: it is content that
crossed the wire for nothing.
"""

from __future__ import annotations

import json
import threading

import pytest

from unified_enforce import Action, Principal, attest, detach
from unified_enforce.audit import AuditChain
from unified_enforce.enforcer import Enforcer
from unified_enforce.evidence import (
    PAYLOADS_FIELD,
    PAYLOADS_PATH,
    EvidenceShipper,
    PayloadShipper,
    payload_shipper,
)
from unified_enforce.policy import Decision, PolicyEngine, Verdict
from unified_enforce.signing import Signer

ACCEPT = {"accepted": 1, "payloads": "accept", "max_payload_bytes": 4096}
REFUSE = {"accepted": 1, "payloads": "refuse", "max_payload_bytes": 0}


class Collecting:
    def __init__(self, receipt=None) -> None:
        self.batches: list[list[dict]] = []
        self.receipt = receipt

    def send(self, batch):
        self.batches.append(list(batch))
        return self.receipt

    @property
    def records(self) -> list[dict]:
        return [r for batch in self.batches for r in batch]


class Broken:
    def __init__(self) -> None:
        self.attempts = 0

    def send(self, batch):
        self.attempts += 1
        raise ConnectionError("control plane unreachable")


def reporter() -> tuple[Signer, str]:
    signer = Signer.generate("chain")
    return signer, attest.b64u(signer.public_bytes())


def entry(value=None, *, path="args", seq=7, record=True, action_digest="a" * 64) -> dict:
    """A written hub-shaped entry: the value detached at `path`, as the chain
    writer leaves it."""
    value = {"path": "/srv/report.csv", "limit": 10} if value is None else value
    body = {"seq": seq, "action_digest": action_digest, path: value}
    out = detach.detach(body, [path], record=record)
    out["hash"] = f"{seq:064x}"
    return out


def gated(sink=None, **kwargs) -> PayloadShipper:
    return PayloadShipper(sink if sink is not None else Collecting(ACCEPT), **kwargs)


# --- the gate -----------------------------------------------------------------


def test_nothing_is_sent_before_the_control_plane_has_answered():
    """Held, not sent: the first receipt has not arrived. A flush in this
    state must not even call the sink."""
    sink = Collecting(ACCEPT)
    payloads = gated(sink)
    signer, _ = reporter()

    payloads.record_payload(entry(), "args", signer=signer)

    assert payloads.mode is None
    assert payloads.flush() == 0
    assert sink.batches == []
    assert len(payloads.spool) == 1, "held for the first receipt, so a restart loses nothing"


def test_a_decision_receipt_that_accepts_opens_the_gate():
    """The whole reporter path: decision evidence ships, its receipt says
    accept, the held payload then ships and verifies against its entry."""
    decisions, payload_sink = Collecting(ACCEPT), Collecting(ACCEPT)
    signer, public = reporter()
    payloads = PayloadShipper(payload_sink)
    shipper = EvidenceShipper(decisions, signer=signer, payloads=payloads)
    written = entry()

    shipper.record_payload(written, "args")
    shipper.submit({"decision": 1})
    shipper.flush()
    assert payloads.accepting and payloads.max_payload_bytes == 4096

    assert payloads.flush() == 1
    (record,) = payload_sink.records
    assert attest.accept_payload_evidence(record, public)
    assert record["chain_seq"] == written["seq"]
    assert record["chain_hash"] == written["hash"]
    assert record["path"] == "args"
    assert record["digest"] == written["detached"]["args"]
    assert record["salt"] == written["salts"]["args"]
    assert record["value"] == written["args"]
    assert record["size_bytes"] == len(detach.canonical(written["args"]))
    assert record["action_digest"] == "a" * 64


def test_a_refusal_discards_what_was_held_and_declines_what_follows():
    sink = Collecting()
    payloads = gated(sink)
    signer, _ = reporter()
    payloads.record_payload(entry(seq=1), "args", signer=signer)
    payloads.record_payload(entry(seq=2), "args", signer=signer)

    payloads.observe(REFUSE)
    assert payloads.flush() == 0
    payloads.record_payload(entry(seq=3), "args", signer=signer)

    assert sink.batches == []
    assert len(payloads.spool) == 0
    assert payloads.payload_stats.declined == 3


@pytest.mark.parametrize(
    "receipt",
    [
        {"accepted": 1},  # a control plane that predates payloads
        {"accepted": 1, "payloads": "yes", "max_payload_bytes": 4096},  # not the word
        {"accepted": 1, "payloads": "accept"},  # no limit to apply
        {"accepted": 1, "payloads": "accept", "max_payload_bytes": 0},
        {"accepted": 1, "payloads": "accept", "max_payload_bytes": "4096"},
        {"accepted": 1, "payloads": "accept", "max_payload_bytes": True},
    ],
    ids=["silent", "unknown-word", "no-limit", "zero-limit", "string-limit", "bool-limit"],
)
def test_anything_but_a_clear_accept_is_a_refusal(receipt):
    """Silence is not consent to receive somebody's tool arguments."""
    payloads = gated()
    payloads.observe(receipt)
    assert payloads.mode == "refuse"
    assert not payloads.accepting


def test_the_gate_closes_when_the_control_plane_changes_its_mind():
    """A fleet switched to `capture off` says so in the next receipt; the
    hub must stop at once, not at its next restart."""
    signer, _ = reporter()
    sink = Collecting(REFUSE)  # the payload endpoint's own answer says refuse
    payloads = gated(sink)
    payloads.observe(ACCEPT)

    payloads.record_payload(entry(seq=1), "args", signer=signer)
    assert payloads.flush() == 1
    assert payloads.mode == "refuse"

    payloads.record_payload(entry(seq=2), "args", signer=signer)
    assert payloads.flush() == 0
    assert len(sink.records) == 1
    assert payloads.payload_stats.declined == 1


def test_records_the_receiver_refuses_are_counted_not_retried():
    signer, _ = reporter()
    sink = Collecting({**ACCEPT, "accepted": 0, "refused": [{"index": 0, "reason": "digest"}]})
    payloads = gated(sink)
    payloads.observe(ACCEPT)
    payloads.record_payload(entry(), "args", signer=signer)

    payloads.flush()
    payloads.flush()

    assert len(sink.batches) == 1
    assert payloads.payload_stats.refused == 1


# --- what is never queued -----------------------------------------------------


def test_a_value_over_the_limit_is_skipped_and_counted():
    signer, _ = reporter()
    sink = Collecting({**ACCEPT, "max_payload_bytes": 64})
    payloads = gated(sink)
    payloads.observe({**ACCEPT, "max_payload_bytes": 64})

    payloads.record_payload(entry({"blob": "x" * 200}, seq=1), "args", signer=signer)
    payloads.record_payload(entry({"ok": 1}, seq=2), "args", signer=signer)
    payloads.flush()

    assert [r["chain_seq"] for r in sink.records] == [2]
    assert payloads.payload_stats.oversize == 1


def test_the_limit_is_applied_again_when_shipping():
    """Held before the first receipt, the limit was not known when the value
    was offered. It is applied when it is."""
    signer, _ = reporter()
    sink = Collecting({**ACCEPT, "max_payload_bytes": 64})
    payloads = gated(sink)
    payloads.record_payload(entry({"blob": "x" * 200}, seq=1), "args", signer=signer)
    payloads.record_payload(entry({"ok": 1}, seq=2), "args", signer=signer)

    payloads.observe({**ACCEPT, "max_payload_bytes": 64})
    payloads.flush()

    assert [r["chain_seq"] for r in sink.records] == [2]
    assert payloads.payload_stats.oversize == 1


def test_nothing_is_sent_without_a_signer():
    """The control plane refuses unsigned payloads; sending one anyway would
    put content on the wire to be thrown away."""
    sink = Collecting(ACCEPT)
    payloads = gated(sink)
    payloads.observe(ACCEPT)

    payloads.record_payload(entry(), "args")  # no signer, none on the shipper
    payloads.flush()

    assert sink.batches == []
    assert payloads.payload_stats.unsigned == 1


def test_the_decision_shippers_signer_is_the_one_used():
    """Unsigned decision shipper, unsigned payloads: no fallback to anything."""
    payload_sink = Collecting(ACCEPT)
    payloads = PayloadShipper(payload_sink)
    payloads.observe(ACCEPT)
    shipper = EvidenceShipper(Collecting(ACCEPT), payloads=payloads)

    shipper.record_payload(entry(), "args")
    payloads.flush()

    assert payload_sink.batches == []
    assert payloads.payload_stats.unsigned == 1


def test_an_unrecorded_value_is_never_sent():
    """`record_payloads=False` keeps the digest and, locally, the salt -- so
    "has a salt" is not "has a value". The signed `unrecorded` list decides."""
    signer, _ = reporter()
    sink = Collecting(ACCEPT)
    payloads = gated(sink)
    payloads.observe(ACCEPT)
    written = entry(record=False)
    assert "args" in written["salts"] and "args" not in written

    payloads.record_payload(written, "args", signer=signer)
    # And a value someone put back beside the unrecorded marker is still not
    # the chain's: the signed entry says it was never stored.
    payloads.record_payload({**written, "args": {"guess": 1}}, "args", signer=signer)
    payloads.flush()

    assert sink.batches == []
    assert payloads.payload_stats.unrecorded == 2


def test_a_path_that_was_never_detached_is_not_sent():
    signer, _ = reporter()
    payloads = gated()
    payloads.observe(ACCEPT)

    payloads.record_payload(entry(), "result", signer=signer)

    assert len(payloads.spool) == 0
    assert payloads.payload_stats.unrecorded == 1


def test_a_value_with_no_action_to_attach_to_is_not_sent():
    signer, _ = reporter()
    payloads = gated()
    payloads.observe(ACCEPT)

    payloads.record_payload(entry(action_digest=""), "args", signer=signer)

    assert len(payloads.spool) == 0


# --- isolation from decisions ---------------------------------------------------


def test_a_broken_payload_stream_costs_decisions_nothing(tmp_path):
    """The payload sink is down, and the payload shipper itself blows up when
    asked to record. Verdicts, the chain and decision evidence are untouched."""
    chain = AuditChain(tmp_path)
    chain.start()
    decisions = Collecting(ACCEPT)
    payloads = PayloadShipper(Broken())

    def explode(*a, **k):
        raise RuntimeError("payload bug")

    payloads._record_payload = explode  # type: ignore[method-assign]
    signer, _ = reporter()
    shipper = EvidenceShipper(decisions, signer=signer, payloads=payloads)
    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    enforcer = Enforcer(engine, chain=chain, evidence=shipper)

    verdict = enforcer.enforce(_action())
    shipper.flush()
    payloads.flush()
    chain.stop()

    assert verdict.verdict.value == "allow"
    assert len(decisions.records) == 1


def test_a_failed_payload_send_requeues_without_touching_decisions():
    signer, _ = reporter()
    broken = Broken()
    payloads = PayloadShipper(broken)
    decisions = Collecting(ACCEPT)
    shipper = EvidenceShipper(decisions, signer=signer, payloads=payloads)

    shipper.record_payload(entry(), "args")
    shipper.submit({"decision": 1})
    assert shipper.flush() == 1
    assert payloads.flush() == 0

    assert broken.attempts == 1
    assert len(payloads.spool) == 1, "requeued, not lost"
    assert len(decisions.records) == 1


def test_a_receipt_that_breaks_the_gate_still_reaches_on_receipt():
    seen = []

    class Exploding(PayloadShipper):
        def observe(self, receipt):
            raise RuntimeError("gate bug")

    shipper = EvidenceShipper(
        Collecting(ACCEPT), payloads=Exploding(Collecting()), on_receipt=seen.append
    )
    shipper.submit({"decision": 1})
    shipper.flush()

    assert seen == [ACCEPT]


def test_the_payload_spool_is_bounded_by_bytes():
    """A run of large results must not hold unbounded memory while the
    control plane is away; the oldest go first, and are counted."""
    signer, _ = reporter()
    payloads = PayloadShipper(Broken(), max_spool_bytes=300)
    for seq in range(1, 6):
        payloads.record_payload(entry({"blob": "x" * 90}, seq=seq), "args", signer=signer)

    held = [r["chain_seq"] for r in payloads.spool.take(10)]
    assert held == [4, 5]
    assert payloads.spool.stats.dropped == 3


def test_stopping_stops_both_streams():
    payloads = PayloadShipper(Collecting(), interval_seconds=0.05)
    shipper = EvidenceShipper(Collecting(), interval_seconds=0.05, payloads=payloads)
    shipper.start()
    assert payloads._thread is not None and payloads._thread.name == "unified-evidence-payloads"

    shipper.stop(timeout=2)

    assert payloads._thread is None and shipper._thread is None


# --- the engine sidecar path -----------------------------------------------------


def _action() -> Action:
    from unified_enforce.action import ActionContext

    return Action.build(
        principal=Principal(id="agent:payments-1"),
        tool="sdk://payments/refund",
        verb="create",
        resource="*",
        params={"amount": "12400.00", "customer": "cus_8812"},
        context=ActionContext(extra={"gateway_header": "x-internal-routing"}),
    )


def test_the_enforcer_ships_params_from_the_entry_it_wrote(tmp_path):
    """`payload.action.params`, bound to the decision entry, verifiable -- and
    not `context.extra`, which stays in the chain."""
    chain = AuditChain(tmp_path)
    chain.start()
    signer, public = reporter()
    payload_sink = Collecting(ACCEPT)
    payloads = PayloadShipper(payload_sink)
    shipper = EvidenceShipper(Collecting(ACCEPT), signer=signer, payloads=payloads)
    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    enforcer = Enforcer(engine, chain=chain, evidence=shipper)
    act = _action()

    enforcer.enforce(act)
    shipper.flush()
    payloads.flush()
    chain.stop()

    (written,) = list(chain.entries())
    (record,) = payload_sink.records
    assert attest.accept_payload_evidence(record, public)
    assert record["path"] == "payload.action.params"
    assert record["value"] == {"amount": "12400.00", "customer": "cus_8812"}
    assert record["action_digest"] == act.digest()
    assert (record["chain_seq"], record["chain_hash"]) == (written["seq"], written["hash"])
    assert record["digest"] == written["detached"]["payload.action.params"]
    assert "x-internal-routing" not in json.dumps(payload_sink.batches)


def test_a_shipper_without_record_payload_still_works_with_the_enforcer(tmp_path):
    """Anything implementing only `record` remains a valid evidence sink."""

    class Minimal:
        def __init__(self) -> None:
            self.seen = 0

        def record(self, action, decision, *, entry=None):
            self.seen += 1

    chain = AuditChain(tmp_path)
    chain.start()
    minimal = Minimal()
    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    Enforcer(engine, chain=chain, evidence=minimal).enforce(_action())  # type: ignore[arg-type]
    chain.stop()

    assert minimal.seen == 1


def test_a_decision_record_never_carries_content_even_with_payloads_on(tmp_path):
    chain = AuditChain(tmp_path)
    chain.start()
    signer, _ = reporter()
    decisions = Collecting(ACCEPT)
    payloads = PayloadShipper(Collecting(ACCEPT))
    shipper = EvidenceShipper(decisions, signer=signer, payloads=payloads)
    engine = PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: all\n    match:\n      tool: '**'\n    effect: allow\n"
    )
    Enforcer(engine, chain=chain, evidence=shipper).enforce(_action())
    shipper.flush()
    chain.stop()

    assert "12400.00" not in json.dumps(decisions.records)


# --- over HTTP ------------------------------------------------------------------


class PayloadReceiver:
    """A payloads endpoint on a real port: checks the path, the body's key and
    the request proof's path, which are what a misrouted sink gets wrong."""

    def __init__(self) -> None:
        from http.server import BaseHTTPRequestHandler, HTTPServer

        self.requests: list[tuple[str, dict, dict]] = []
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                receiver.requests.append((self.path, body, dict(self.headers)))
                self.send_response(202)
                self.end_headers()
                self.wfile.write(json.dumps(ACCEPT).encode())

            def log_message(self, *args):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def test_payloads_post_to_their_endpoint_with_the_request_proof():
    receiver = PayloadReceiver()
    proved: list[tuple[str, str]] = []

    class Channel:
        def headers(self, method, path, body):
            proved.append((method, path))
            return {"x-unified-proof": "proof"}

    try:
        signer, public = reporter()
        payloads = payload_shipper(receiver.url, "uai_sc_test", channel=Channel())
        payloads.observe(ACCEPT)
        payloads.record_payload(entry(), "args", signer=signer)

        assert payloads.flush() == 1
    finally:
        receiver.close()

    ((path, body, headers),) = receiver.requests
    assert path == PAYLOADS_PATH
    assert list(body) == [PAYLOADS_FIELD]
    assert attest.accept_payload_evidence(body[PAYLOADS_FIELD][0], public)
    assert proved == [("POST", PAYLOADS_PATH)]
    assert headers.get("X-Unified-Proof") == "proof"


def test_a_decision_is_unaffected_by_a_payload_shipper_that_was_never_started():
    """Shipping decisions on their own thread does not depend on the payload
    stream having a thread at all."""
    decisions = Collecting(ACCEPT)
    shipper = EvidenceShipper(decisions, payloads=PayloadShipper(Broken()))
    shipper.record(_action(), Decision(verdict="allow", rule_id="all", source="rule"))
    assert shipper.flush() == 1


# --- the gate, per batch ----------------------------------------------------------
#
# A flush can run for many batches, and what may be sent can change between
# them: a payload response that says refuse, a decision receipt on the other
# thread, a lower limit. The gate is re-read before every batch.


def _held(payloads: PayloadShipper, n: int, signer, value=None) -> None:
    for seq in range(1, n + 1):
        payloads.record_payload(entry(value, seq=seq), "args", signer=signer)


def test_a_refusal_in_a_payload_response_stops_the_rest_of_the_flush():
    class RefusesAfterFirst(Collecting):
        def send(self, batch):
            self.batches.append(list(batch))
            return {"accepted": len(batch), "refused": [], **REFUSE}

    sink = RefusesAfterFirst()
    payloads = gated(sink, batch_size=1)
    signer, _ = reporter()
    _held(payloads, 3, signer)
    payloads.observe(ACCEPT)

    assert payloads.flush() == 1
    assert len(sink.batches) == 1, "the batches after the refusal were sent anyway"
    assert len(payloads.spool) == 0
    assert payloads.payload_stats.declined == 2


def test_a_refusal_on_the_decision_thread_stops_the_rest_of_the_flush():
    """The decision stream's receipt lands on its own thread, between two of
    this stream's batches. Simulated inside the send, which is exactly the
    window: after one batch was taken, before the next."""
    signer, _ = reporter()

    class Elsewhere(Collecting):
        def send(self, batch):
            self.batches.append(list(batch))
            payloads.observe(REFUSE)  # the other thread
            return None

    sink = Elsewhere()
    payloads = gated(sink, batch_size=1)
    _held(payloads, 3, signer)
    payloads.observe(ACCEPT)

    payloads.flush()

    assert len(sink.batches) == 1
    assert payloads.payload_stats.declined == 2


def test_a_limit_lowered_mid_flush_applies_to_the_next_batch():
    signer, _ = reporter()
    value = {"path": "/srv/report.csv", "limit": 10}
    size = len(detach.canonical(value))

    class Lowers(Collecting):
        def send(self, batch):
            self.batches.append(list(batch))
            payloads.observe({"payloads": "accept", "max_payload_bytes": size - 1})
            return None

    sink = Lowers()
    payloads = gated(sink, batch_size=1)
    _held(payloads, 3, signer, value)
    payloads.observe(ACCEPT)

    payloads.flush()

    assert len(sink.batches) == 1
    assert payloads.payload_stats.oversize == 2


def test_the_gate_writes_the_limit_before_the_mode():
    """A reader on another thread checks `mode`, then the limit. Writing mode
    first opened a window where "accept" sat beside the previous limit -- a
    refusal's 0, or a larger limit the receiver had just lowered."""
    order: list[str] = []

    class Watched(PayloadShipper):
        def __setattr__(self, name, value):
            if name in ("mode", "max_payload_bytes"):
                order.append(name)
            super().__setattr__(name, value)

    payloads = Watched(Collecting())
    order.clear()
    payloads.observe(ACCEPT)

    assert order == ["max_payload_bytes", "mode"]


# --- bounded by bytes ---------------------------------------------------------------


def test_a_batch_is_bounded_by_bytes_as_well_as_count():
    signer, _ = reporter()
    value = {"blob": "x" * 1000}
    size = len(detach.canonical(value))
    sink = Collecting(ACCEPT)
    payloads = gated(sink, batch_size=20, batch_bytes=size * 2)
    _held(payloads, 5, signer, value)
    payloads.observe(ACCEPT)

    assert payloads.flush() == 5
    assert [len(b) for b in sink.batches] == [2, 2, 1]


def test_a_413_splits_the_batch_and_drops_only_a_record_too_large_alone():
    from unified_enforce.evidence import PayloadTooLarge

    signer, public = reporter()
    small, big = {"v": "s"}, {"v": "b" * 200}

    class Proxy(Collecting):
        """A proxy that turns away any body over ~300 bytes of values."""

        def send(self, batch):
            if sum(r["size_bytes"] for r in batch) > 300:
                raise PayloadTooLarge("HTTP 413: Request Entity Too Large")
            return super().send(batch)

    sink = Proxy(ACCEPT)
    payloads = gated(sink, batch_size=20)
    for seq, value in enumerate([small, big, small, big, big, small], start=1):
        payloads.record_payload(entry(value, seq=seq), "args", signer=signer)
    payloads.record_payload(entry({"v": "z" * 400}, seq=99), "args", signer=signer)
    payloads.observe(ACCEPT)

    shipped = payloads.flush()

    assert shipped == 6
    assert sorted(r["chain_seq"] for r in sink.records) == [1, 2, 3, 4, 5, 6]
    assert all(attest.accept_payload_evidence(r, public) for r in sink.records)
    assert payloads.payload_stats.oversize == 1, "the one record too large alone"
    assert len(payloads.spool) == 0


def test_the_http_sink_reports_413_as_too_large():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from unified_enforce.evidence import HttpSink, PayloadTooLarge

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            self.send_response(413)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        sink = HttpSink(f"http://127.0.0.1:{server.server_port}", "t", path=PAYLOADS_PATH)
        with pytest.raises(PayloadTooLarge):
            sink.send([{"v": 1}])
    finally:
        server.shutdown()
        server.server_close()


# --- what ships is what was hashed --------------------------------------------------


def test_values_json_cannot_carry_ship_as_the_chain_hashed_them():
    """A date, a Decimal, bytes: the chain's canonical form stringifies them
    (detach.canonical, default=str). Shipping the original objects made the
    sink's json.dumps raise, and the batch was requeued at the head of the
    stream forever. What ships now is the hashed bytes, parsed back."""
    import datetime
    import decimal

    signer, public = reporter()
    value = {
        "when": datetime.date(2026, 10, 5),
        "amount": decimal.Decimal("12400.00"),
        "blob": b"\x00\x01",
    }
    written = entry(value)

    class Serialising(Collecting):
        def send(self, batch):
            json.dumps({PAYLOADS_FIELD: batch})  # what HttpSink does
            return super().send(batch)

    sink = Serialising(ACCEPT)
    payloads = gated(sink)
    payloads.observe(ACCEPT)
    payloads.record_payload(written, "args", signer=signer)

    assert payloads.flush() == 1
    (record,) = sink.records
    assert record["value"] == json.loads(detach.canonical(value))
    assert attest.accept_payload_evidence(json.loads(json.dumps(record)), public)


def test_a_batch_that_cannot_be_serialised_is_discarded_not_requeued():
    from unified_enforce.evidence import HttpSink, PermanentRejection

    # Nothing listens here; serialisation fails before any connection.
    sink = HttpSink("https://127.0.0.1:9", "t", path=PAYLOADS_PATH, field=PAYLOADS_FIELD)
    with pytest.raises(PermanentRejection):
        sink.send([{"value": object()}])

    shipper = EvidenceShipper(sink)
    shipper.submit({"value": object()})
    assert shipper.flush() == 0
    assert len(shipper.spool) == 0, "put back, it would block the stream forever"
    assert shipper.spool.stats.rejected == 1


# --- pending bounds ---------------------------------------------------------------


def test_a_large_value_is_not_held_while_nobody_has_answered():
    signer, _ = reporter()
    payloads = gated(pending_max_bytes=64)

    payloads.record_payload(entry({"blob": "x" * 100}), "args", signer=signer)
    payloads.record_payload(entry({"v": 1}, seq=8), "args", signer=signer)

    assert len(payloads.spool) == 1
    assert payloads.payload_stats.oversize == 1


def test_a_record_heavier_than_the_whole_spool_is_refused_without_evicting():
    """Admitting it evicted every queued record to make room and then held
    more than the bound anyway."""
    from unified_enforce.evidence import EvidenceSpool

    spool = EvidenceSpool(capacity=100, max_bytes=100, weigh=lambda r: r["w"])
    assert spool.add({"w": 30})
    assert spool.add({"w": 30})

    assert spool.add({"w": 101}) is False
    assert len(spool) == 2
    assert spool.stats.dropped == 1


def test_a_receiver_that_never_sends_a_receipt_settles_the_gate_to_refuse():
    """Held values wait for the first receipt. A decision sink that returns
    nothing would have held them for the life of the process."""
    from unified_enforce.evidence import PENDING_SILENT_RECEIPTS

    signer, _ = reporter()
    payloads = PayloadShipper(Collecting(ACCEPT))
    shipper = EvidenceShipper(Collecting(None), signer=signer, payloads=payloads)
    shipper.record_payload(entry(), "args")

    for n in range(PENDING_SILENT_RECEIPTS):
        assert payloads.mode is None, f"settled after only {n} silent batch(es)"
        shipper.submit({"decision": n})
        shipper.flush()

    assert payloads.mode == "refuse"
    assert payloads.flush() == 0
    assert len(payloads.spool) == 0
    assert payloads.payload_stats.declined == 1


# --- the decision path, guarded ---------------------------------------------------


def _allow_all() -> PolicyEngine:
    return PolicyEngine.from_yaml(
        "version: 1\nrules:\n  - id: all\n    match:\n      tool: '**'\n    effect: allow\n"
    )


def test_a_custom_record_payload_that_raises_cannot_fail_a_decision(tmp_path):
    class Hostile:
        def record(self, action, decision, *, entry=None):
            return True

        def record_payload(self, *a, **k):
            raise RuntimeError("custom shipper bug")

    chain = AuditChain(tmp_path)
    chain.start()
    try:
        enforcer = Enforcer(_allow_all(), chain=chain, evidence=Hostile())  # type: ignore[arg-type]
        assert enforcer.enforce(_action()).verdict.value == "allow"
    finally:
        chain.stop()


def _offered(tmp_path, decide) -> list:
    """Run `decide(enforcer, action)` with a payload stream; return what it offered."""
    offered: list = []

    class Watching:
        def record(self, action, decision, *, entry=None):
            return True

        def record_payload(self, entry, path, **kwargs):
            offered.append(path)

    chain = AuditChain(tmp_path)
    chain.start()
    try:
        decide(Enforcer(_allow_all(), chain=chain, evidence=Watching()), _action())  # type: ignore[arg-type]
    finally:
        chain.stop()
    return offered


def test_a_finding_ships_no_payload(tmp_path):
    """`count=False` records describe an action already decided; their params
    are an empty placeholder, not arguments."""
    finding = Decision(verdict=Verdict.ALLOW, rule_id=None, source="injection_suspected")
    assert _offered(tmp_path / "a", lambda e, a: e.record(a, finding)) == [
        "payload.action.params"
    ], "guards the negative below"
    assert _offered(tmp_path / "b", lambda e, a: e.record(a, finding, count=False)) == []


def test_a_minimal_rule_ships_no_payload(tmp_path):
    """The customer marked this traffic sensitive. The chain keeps it; no copy
    leaves."""
    minimal = Decision(verdict=Verdict.ALLOW, rule_id="all", source="rule", audit_level="minimal")
    assert _offered(tmp_path, lambda e, a: e.record(a, minimal)) == []


def test_no_payload_is_offered_for_a_decision_that_was_not_queued(tmp_path):
    class Failing:
        def record(self, action, decision, *, entry=None):
            return False

        def record_payload(self, *a, **k):
            raise AssertionError("offered a payload for a row that never left")

    chain = AuditChain(tmp_path)
    chain.start()
    try:
        Enforcer(_allow_all(), chain=chain, evidence=Failing()).enforce(_action())  # type: ignore[arg-type]
    finally:
        chain.stop()


def test_record_reports_whether_the_row_was_queued():
    shipper = EvidenceShipper(Collecting())
    decision = Decision(verdict="allow", rule_id="all", source="rule")
    assert shipper.record(_action(), decision) is True

    from unified_enforce.action import ActionContext

    floats = Action.build(
        principal=Principal(id="agent:x"),
        tool="mcp://fs/read",
        verb="call",
        resource="*",
        params={"temp": 0.7},
        context=ActionContext(),
    )
    # The strict digest refuses floats; without an override the row is lost,
    # and record() now says so instead of returning None either way.
    assert shipper.record(floats, decision) is False
    assert shipper.record(floats, decision, action_digest=floats.digest(strict=False)) is True
    assert shipper.spool.take(10)[-1]["action_digest"] == floats.digest(strict=False)


# --- https only -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://cp.example.com", True),
        ("http://cp.example.com", False),
        ("http://10.0.0.5:8080", False),
        ("http://localhost:8080", True),
        ("http://127.0.0.1:8080", True),
        ("http://[::1]:8080", True),
        ("ftp://cp.example.com", False),
        ("https://", False),
        ("", False),
    ],
)
def test_payloads_need_https_except_to_this_machine(url, ok):
    from unified_enforce.evidence import payload_transport_ok

    assert payload_transport_ok(url) is ok
    if ok:
        payload_shipper(url, "t")
    else:
        with pytest.raises(ValueError):
            payload_shipper(url, "t")


# --- shutdown -------------------------------------------------------------------------


def test_the_payload_stream_has_its_own_shutdown_wording(caplog):
    release = threading.Event()

    class Stuck:
        def send(self, batch):
            release.wait(5)
            return ACCEPT

    signer, _ = reporter()
    payloads = PayloadShipper(Stuck(), interval_seconds=0.01)
    payloads.observe(ACCEPT)
    payloads.record_payload(entry(), "args", signer=signer)
    payloads.start()
    try:
        for _ in range(200):
            if len(payloads.spool) == 0:
                break
            threading.Event().wait(0.01)
        with caplog.at_level("WARNING", logger="unified_enforce.evidence"):
            payloads.stop(timeout=0.05)
    finally:
        release.set()

    assert any("payload evidence worker still shipping" in r.message for r in caplog.records)


def test_a_slow_decision_stream_does_not_make_the_payload_stream_warn(caplog):
    """The decision stream may use the whole budget (here, a final flush stuck
    on a slow receiver). The payload stream then got a join of zero seconds
    and reported a worker that was merely waking up as "still shipping" -- a
    spurious warning, worded exactly like the decision stream's."""
    release = threading.Event()

    class Slow(Collecting):
        def send(self, batch):
            release.wait(2)
            return super().send(batch)

    payloads = PayloadShipper(Collecting(), interval_seconds=60)
    shipper = EvidenceShipper(Slow(), interval_seconds=60, payloads=payloads)
    shipper.start()
    shipper.submit({"decision": 1})
    try:
        with caplog.at_level("WARNING", logger="unified_enforce.evidence"):
            shipper.stop(timeout=0.1)
    finally:
        release.set()

    warnings = [r.getMessage() for r in caplog.records]
    assert any("final evidence flush" in w for w in warnings), "guards the negative below"
    assert not [w for w in warnings if "worker still shipping" in w], warnings
