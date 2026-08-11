import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from unified_enforce import (
    Action,
    ActionContext,
    AuditChain,
    Enforcer,
    PolicyEngine,
    Principal,
    Telemetry,
)

POLICY = """
version: 1
rules:
  - {id: reads-ok, match: {tool: "mcp://github/*", verb: read}, effect: allow}
  - id: refunds-capped
    match: {tool: "sdk://payments/refund"}
    when: 'int(params.amount_cents) <= 5000'
    effect: allow
"""


def act(tool="mcp://github/list_prs", verb="read", params=None, context=None):
    return Action.build(
        principal=Principal(id="agent:x"),
        tool=tool,
        verb=verb,
        resource="*",
        params=params or {},
        context=context or ActionContext(),
    )


@pytest.fixture
def exporter():
    return InMemorySpanExporter()


@pytest.fixture
def telemetry(exporter):
    t = Telemetry(exporter=exporter)
    yield t
    t.shutdown()


@pytest.fixture
def engine():
    return PolicyEngine.from_yaml(POLICY)


def test_allow_span_attributes(engine, telemetry, exporter):
    action = act()
    decision = engine.decide(action)
    telemetry.record_decision(action, decision)
    (span,) = exporter.get_finished_spans()
    assert span.name == "enforce.decide mcp://github/list_prs"
    a = span.attributes
    assert a["unified.verdict"] == "allow"
    assert a["unified.rule_id"] == "reads-ok"
    assert a["unified.action.digest"] == action.digest()
    assert a["langfuse.observation.level"] == "DEFAULT"


def test_deny_and_condition_error_levels(engine, telemetry, exporter):
    denied = act(tool="mcp://slack/post", verb="call")
    telemetry.record_decision(denied, engine.decide(denied))
    broken = act(tool="sdk://payments/refund", verb="call", params={})  # missing amount
    telemetry.record_decision(broken, engine.decide(broken))
    deny_span, error_span = exporter.get_finished_spans()
    assert deny_span.attributes["langfuse.observation.level"] == "WARNING"
    assert error_span.attributes["langfuse.observation.level"] == "ERROR"
    assert error_span.attributes["unified.decision.source"] == "condition_error"


def test_span_parents_into_callers_trace(engine, telemetry, exporter):
    trace_id = "0af7651916cd43dd8448eb211c80319c"
    span_id = "b7ad6b7169203331"
    action = act(context=ActionContext(origin="mcp", trace_id=trace_id, span_id=span_id))
    telemetry.record_decision(action, engine.decide(action))
    (span,) = exporter.get_finished_spans()
    assert format(span.context.trace_id, "032x") == trace_id
    assert format(span.parent.span_id, "016x") == span_id
    assert span.parent.is_remote


def test_malformed_trace_ids_never_break_emission(engine, telemetry, exporter):
    action = act(context=ActionContext(trace_id="not-hex", span_id="nope"))
    telemetry.record_decision(action, engine.decide(action))
    (span,) = exporter.get_finished_spans()
    assert span.parent is None


def test_float_params_do_not_break_span_emission(engine, telemetry, exporter):
    """MCP tool arguments are free-form JSON and may hold floats, which strict
    canonicalization refuses. The span digest is a correlation key, not
    evidence, so it is computed leniently — a strict one would crash the call
    path of every integration with free-form params."""
    action = act(params={"threshold": 0.75})
    telemetry.record_decision(action, engine.decide(action))
    (span,) = exporter.get_finished_spans()
    assert len(span.attributes["unified.action.digest"]) == 64


def test_the_span_digest_matches_the_audit_entry_it_points_at(engine, telemetry, exporter):
    """The whole point of carrying a digest on the span: joining it to the
    chained record of the same action."""
    action = act(params={"threshold": 0.75})
    telemetry.record_decision(action, engine.decide(action))
    (span,) = exporter.get_finished_spans()
    assert span.attributes["unified.action.digest"] == action.digest(strict=False)


def test_disabled_telemetry_is_a_noop(engine):
    t = Telemetry.disabled()
    assert not t.enabled
    t.record_decision(act(), engine.decide(act()))  # must not raise
    t.shutdown()


def test_langfuse_constructor_builds_basic_auth(monkeypatch):
    captured = {}

    class FakeExporter:
        def __init__(self, endpoint=None, headers=None):
            captured["endpoint"] = endpoint
            captured["headers"] = headers

        def export(self, spans):  # pragma: no cover - never driven in this test
            pass

        def shutdown(self):
            pass

    import opentelemetry.exporter.otlp.proto.http.trace_exporter as m

    monkeypatch.setattr(m, "OTLPSpanExporter", FakeExporter)
    t = Telemetry.for_langfuse("https://langfuse.internal/", "pk-lf-1", "sk-lf-2")
    t.shutdown()
    assert captured["endpoint"] == "https://langfuse.internal/api/public/otel/v1/traces"
    import base64

    expected = base64.b64encode(b"pk-lf-1:sk-lf-2").decode()
    assert captured["headers"]["Authorization"] == f"Basic {expected}"


def test_enforcer_records_to_chain_and_telemetry(tmp_path, engine, telemetry, exporter):
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        enforcer = Enforcer(engine, chain=chain, telemetry=telemetry)
        decision = enforcer.enforce(act())
        assert decision.verdict.value == "allow"
        assert len(exporter.get_finished_spans()) == 1
        assert AuditChain.verify(tmp_path / "audit").ok
    finally:
        chain.stop()


def test_enforcer_audit_failure_still_emits_span_then_raises(engine, telemetry, exporter):
    chain = AuditChain("/nonexistent")  # never started → append raises
    enforcer = Enforcer(engine, chain=chain, telemetry=telemetry)
    with pytest.raises(RuntimeError, match="not started"):
        enforcer.enforce(act())
    assert len(exporter.get_finished_spans()) == 1  # evidence of the decision survives
