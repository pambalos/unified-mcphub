"""The OTLP wire path — the real exporter, really serializing, really posting.

Everything else in the telemetry suite uses InMemorySpanExporter, which skips
protobuf encoding and HTTP entirely. So until this file existed, nothing
exercised what actually goes over the wire: whether our attribute values are
types OTLP accepts, whether `for_langfuse` derives a path a server would route,
whether the Basic-auth header survives, or whether shutdown() flushes the
batch. "We support Langfuse" rested on a monkeypatched exporter asserting a
URL string.

This tier needs no containers. tests/integration/test_otlp_backends.py takes
the same spans to a real OTel Collector and a real Langfuse.
"""

from __future__ import annotations

import gzip
import http.server
import threading

import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from unified_enforce import Action, ActionContext, PolicyEngine, Principal, Telemetry

POLICY = """
version: 1
rules:
  - {id: reads-ok, match: {tool: "mcp://github/list_prs", verb: read}, effect: allow}
  - {id: payouts, match: {tool: "mcp://bank/payout"}, effect: defer}
"""


class _Receiver(http.server.BaseHTTPRequestHandler):
    """Stands in for any OTLP/HTTP collector: capture, decode, 200."""

    posts: list[tuple[str, dict[str, str], bytes]] = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.headers.get("content-encoding") == "gzip":
            body = gzip.decompress(body)
        type(self).posts.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *args):  # silence
        pass


@pytest.fixture
def collector():
    _Receiver.posts = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def act(tool="mcp://github/list_prs", verb="read", context=None):
    return Action.build(
        principal=Principal(id="agent:crew-1"),
        tool=tool,
        verb=verb,
        resource="*",
        params={"threshold": 0.75},  # a float: free-form params must survive the wire
        context=context or ActionContext(origin="mcp"),
    )


def emit(telemetry: Telemetry, action=None) -> None:
    """Record one decision and flush the batch."""
    engine = PolicyEngine.from_yaml(POLICY)
    action = action or act()
    telemetry.record_decision(action, engine.decide(action))
    telemetry.shutdown()  # BatchSpanProcessor: nothing leaves until this runs


def decode(body: bytes) -> ExportTraceServiceRequest:
    request = ExportTraceServiceRequest()
    request.ParseFromString(body)
    return request


def only_span(request: ExportTraceServiceRequest):
    (resource_spans,) = request.resource_spans
    (scope_spans,) = resource_spans.scope_spans
    (span,) = scope_spans.spans
    return resource_spans, span


def attrs(span) -> dict[str, object]:
    out: dict[str, object] = {}
    for kv in span.attributes:
        field = kv.value.WhichOneof("value")
        out[kv.key] = getattr(kv.value, field) if field else None
    return out


# --- the wire itself ---


def test_a_decision_really_serializes_and_posts(collector):
    emit(Telemetry(endpoint=f"http://127.0.0.1:{collector}/v1/traces"))

    assert _Receiver.posts, "nothing was exported — the batch never flushed"
    path, headers, body = _Receiver.posts[0]
    assert path == "/v1/traces"
    assert headers["content-type"] == "application/x-protobuf"

    _, span = only_span(decode(body))
    assert span.name == "enforce.decide mcp://github/list_prs"


def test_every_attribute_survives_the_protobuf_round_trip(collector):
    emit(Telemetry(endpoint=f"http://127.0.0.1:{collector}/v1/traces"))
    _, span = only_span(decode(_Receiver.posts[0][2]))
    a = attrs(span)

    assert a["unified.verdict"] == "allow"
    assert a["unified.rule_id"] == "reads-ok"
    assert a["unified.principal.id"] == "agent:crew-1"
    assert a["unified.tool"] == "mcp://github/list_prs"
    assert a["unified.decision.source"] == "exact"
    assert a["langfuse.observation.level"] == "DEFAULT"
    assert len(a["unified.action.digest"]) == 64


def test_float_params_do_not_break_the_wire_path(collector):
    """The action carries a float. OTLP attribute values are a constrained
    union, so anything derived from params has to already be a string — this is
    the end-to-end proof that the lenient digest holds up all the way to the
    wire, and that it is the digest an auditor can join on.
    """
    action = act()  # one action, so its digest is a fixed value to compare against
    emit(Telemetry(endpoint=f"http://127.0.0.1:{collector}/v1/traces"), action)
    _, span = only_span(decode(_Receiver.posts[0][2]))
    assert attrs(span)["unified.action.digest"] == action.digest(strict=False)


def test_service_name_lands_on_the_resource(collector):
    emit(Telemetry(endpoint=f"http://127.0.0.1:{collector}/v1/traces", service_name="unified-hub"))
    resource_spans, _ = only_span(decode(_Receiver.posts[0][2]))
    names = {kv.key: kv.value.string_value for kv in resource_spans.resource.attributes}
    assert names["service.name"] == "unified-hub"


def test_a_deny_is_flagged_for_langfuse_over_the_wire(collector):
    telemetry = Telemetry(endpoint=f"http://127.0.0.1:{collector}/v1/traces")
    emit(telemetry, act(tool="mcp://bank/payout", verb="call"))
    _, span = only_span(decode(_Receiver.posts[0][2]))
    a = attrs(span)
    assert a["unified.verdict"] == "defer"
    assert a["langfuse.observation.level"] == "WARNING"


def test_the_callers_trace_id_survives_as_the_spans_own(collector):
    """A gateway or hub verdict has to land *inside* the agent's trace, not
    beside it — otherwise the DENY is invisible where anyone would look."""
    trace_id = "0af7651916cd43dd8448eb211c80319c"
    emit(
        Telemetry(endpoint=f"http://127.0.0.1:{collector}/v1/traces"),
        act(context=ActionContext(origin="gateway", trace_id=trace_id, span_id="b7ad6b7169203331")),
    )
    _, span = only_span(decode(_Receiver.posts[0][2]))
    assert span.trace_id.hex() == trace_id
    assert span.parent_span_id.hex() == "b7ad6b7169203331"


# --- the Langfuse contract specifically ---


def test_for_langfuse_posts_to_the_path_it_derives(collector):
    """`for_langfuse` builds the OTLP path from a bare host. If that derivation
    is wrong the exporter 404s silently — a batch exporter swallows it."""
    emit(Telemetry.for_langfuse(f"http://127.0.0.1:{collector}", "pk-lf-1", "sk-lf-2"))

    path, headers, body = _Receiver.posts[0]
    assert path == "/api/public/otel/v1/traces"
    assert headers["authorization"] == "Basic cGstbGYtMTpzay1sZi0y"  # pk-lf-1:sk-lf-2
    only_span(decode(body))  # and it is still a well-formed export


def test_a_trailing_slash_on_the_host_does_not_double_up(collector):
    emit(Telemetry.for_langfuse(f"http://127.0.0.1:{collector}/", "pk", "sk"))
    assert _Receiver.posts[0][0] == "/api/public/otel/v1/traces"


def test_shutdown_flushes_rather_than_dropping(collector):
    """BatchSpanProcessor holds spans in memory. A hub that exits without
    flushing loses the last decisions it made — exactly the ones an incident
    review wants."""
    telemetry = Telemetry(endpoint=f"http://127.0.0.1:{collector}/v1/traces")
    engine = PolicyEngine.from_yaml(POLICY)
    for _ in range(3):
        action = act()
        telemetry.record_decision(action, engine.decide(action))
    assert _Receiver.posts == [], "batch should not have left yet"
    telemetry.shutdown()
    exported = sum(
        len(s.spans)
        for p in _Receiver.posts
        for r in decode(p[2]).resource_spans
        for s in r.scope_spans
    )
    assert exported == 3
