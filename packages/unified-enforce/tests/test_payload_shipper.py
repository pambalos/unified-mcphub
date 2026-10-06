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
from unified_enforce.policy import Decision, PolicyEngine
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
