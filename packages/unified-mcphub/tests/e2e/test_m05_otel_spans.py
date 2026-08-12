"""The hub really emits decision spans — UAI-142, M0.5.

The wiring in UAI-86 was unit-verified: `AuthzResolver` + `Telemetry`, and
`_build_telemetry` in isolation. That left the path a *deployment* actually
takes — config says `otel.enabled`, a tool call arrives over the socket, a span
leaves the process — unproven end to end. Not an academic distinction here:
wiring it up surfaced a crash-on-float in `record_decision`, because MCP
arguments are free-form JSON and the digest was computed strictly.

So this exercises the whole path against a **real OTLP exporter** posting to a
local receiver, and decodes the protobuf it actually sent. A mocked exporter
would skip encoding, which is where that class of bug lives.
"""

from __future__ import annotations

import gzip
import http.server
import threading

import httpx
import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub

ALLOWED = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "filesystem__list_files", "arguments": {"path": "/tmp", "depth": 1.5}},
}
DENIED = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "filesystem__read_file", "arguments": {"path": "/etc/passwd"}},
}


class _Receiver(http.server.BaseHTTPRequestHandler):
    posts: list[bytes] = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.headers.get("content-encoding") == "gzip":
            body = gzip.decompress(body)
        type(self).posts.append(body)
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def collector():
    _Receiver.posts = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def _spans() -> list:
    out = []
    for body in _Receiver.posts:
        request = ExportTraceServiceRequest()
        request.ParseFromString(body)
        for resource_spans in request.resource_spans:
            for scope_spans in resource_spans.scope_spans:
                out.extend(scope_spans.spans)
    return out


def _attrs(span) -> dict[str, object]:
    values = {}
    for kv in span.attributes:
        field = kv.value.WhichOneof("value")
        values[kv.key] = getattr(kv.value, field) if field else None
    return values


def _client(sock):
    transport = httpx.AsyncHTTPTransport(uds=str(sock))
    return httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=20)


async def _run_calls(hub_home, collector_port, calls):
    config = load_config()
    config.hub.otel.enabled = True
    config.hub.otel.endpoint = f"http://127.0.0.1:{collector_port}/v1/traces"
    config.hub.otel.service_name = "unified-mcphub-test"
    hub = Hub(config)
    await hub.start()
    try:
        async with _client(config.hub.listen.unix_socket) as client:
            for call in calls:
                await client.post("/mcp", json=call, headers={"X-Caller-Id": "claude-code"})
    finally:
        # stop() flushes the batch; without it the spans are still in memory and
        # the assertions below would race the exporter.
        await hub.stop()


@pytest.mark.asyncio
async def test_an_allowed_call_emits_a_decision_span(hub_home, collector):
    await _run_calls(hub_home, collector, [ALLOWED])

    spans = _spans()
    assert spans, "the hub produced no spans with otel.enabled"
    (span,) = [s for s in spans if s.name.startswith("enforce.decide")]
    assert span.name == "enforce.decide mcp://filesystem/list_files"

    attrs = _attrs(span)
    assert attrs["unified.verdict"] == "allow"
    assert attrs["unified.principal.id"] == "agent:claude-code"
    assert attrs["unified.tool"] == "mcp://filesystem/list_files"


@pytest.mark.asyncio
async def test_float_arguments_do_not_break_the_hot_path(hub_home, collector):
    """`depth: 1.5` in the call above is deliberate.

    MCP arguments are free-form JSON. A strict action digest raises on floats,
    which would have turned every such tool call into a 500 the moment an
    operator enabled telemetry — the exact bug the wiring introduced and this
    asserts stays fixed.
    """
    await _run_calls(hub_home, collector, [ALLOWED])
    (span,) = [s for s in _spans() if s.name.startswith("enforce.decide")]
    assert len(_attrs(span)["unified.action.digest"]) == 64


@pytest.mark.asyncio
async def test_a_denied_call_is_visible_as_a_warning(hub_home, collector):
    """The event an operator most needs in a trace is the one that was blocked."""
    await _run_calls(hub_home, collector, [DENIED])

    (span,) = [s for s in _spans() if s.name.startswith("enforce.decide")]
    attrs = _attrs(span)
    assert attrs["unified.verdict"] == "deny"
    assert attrs["langfuse.observation.level"] == "WARNING"
    assert attrs["langfuse.observation.status_message"] == "deny (default)"


@pytest.mark.asyncio
async def test_otel_off_by_default_emits_nothing(hub_home, collector):
    """The default deployment must not need a collector, or the extra."""
    config = load_config()
    assert config.hub.otel.enabled is False
    config.hub.otel.endpoint = f"http://127.0.0.1:{collector}/v1/traces"
    hub = Hub(config)
    await hub.start()
    try:
        async with _client(config.hub.listen.unix_socket) as client:
            await client.post("/mcp", json=ALLOWED, headers={"X-Caller-Id": "claude-code"})
    finally:
        await hub.stop()

    assert _Receiver.posts == [], "telemetry was exported with otel disabled"
