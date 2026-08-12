"""UAI-86: the hub emits decision spans.

The engine has had OTel decision spans since UAI-116, but the hub never used
them — it drove the policy engine directly, so the one product actually running
the enforcement plane produced no traces. These tests pin the wiring.
"""

from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from unified_enforce import Telemetry
from unified_mcphub.authz import AuthzResolver, Effect
from unified_mcphub.config import Authz, DangerousCommands, OtelConfig, Rule, Workspace
from unified_mcphub.hub import _build_telemetry


@pytest.fixture
def exporter():
    return InMemorySpanExporter()


@pytest.fixture
def telemetry(exporter):
    t = Telemetry(exporter=exporter)
    yield t
    t.shutdown()


def resolver(telemetry=None, rules=None, danger=None) -> AuthzResolver:
    return AuthzResolver(
        Workspace(authz=Authz(rules=rules or [])),
        DangerousCommands(require_approval=danger or []),
        telemetry=telemetry,
    )


def test_a_hub_decision_emits_a_span(telemetry, exporter):
    r = resolver(telemetry, [Rule(tool="mcp://fs/read_*", effect="allow")])
    assert r.resolve("mcp://fs/read_file", {"path": "/tmp/x"}, "claude-code").effect is Effect.ALLOW

    (span,) = exporter.get_finished_spans()
    assert span.name == "enforce.decide mcp://fs/read_file"
    assert span.attributes["unified.verdict"] == "allow"
    assert span.attributes["unified.principal.id"] == "agent:claude-code"


def test_denials_and_prompts_are_visible_as_warnings(telemetry, exporter):
    """A blocked call is the event an operator most needs to see in a trace."""
    r = resolver(telemetry, danger=["mcp://shell/execute_command"])
    r.resolve("mcp://github/create_issue", {}, "x")  # default deny
    r.resolve("mcp://shell/execute_command", {"command": "rm -rf /"}, "x")  # floor -> defer

    deny, defer = exporter.get_finished_spans()
    assert deny.attributes["unified.verdict"] == "deny"
    assert defer.attributes["unified.verdict"] == "defer"
    # Langfuse renders these as warnings rather than plain events.
    assert deny.attributes["langfuse.observation.level"] == "WARNING"
    assert defer.attributes["langfuse.observation.level"] == "WARNING"


def test_float_arguments_do_not_break_the_call_path(telemetry, exporter):
    """MCP tool arguments are free-form JSON. A float in them must not raise on
    the hot path — the span digest is computed leniently for exactly this."""
    r = resolver(telemetry, [Rule(tool="mcp://*/*", effect="allow")])
    d = r.resolve("mcp://sampler/run", {"temperature": 0.7}, "x")
    assert d.effect is Effect.ALLOW
    (span,) = exporter.get_finished_spans()
    assert len(span.attributes["unified.action.digest"]) == 64


def test_the_hub_action_reaches_the_span_unchanged(telemetry, exporter):
    """The resolver decides on the Action the hub built, so the span's digest
    must match the one the hub writes into its audit entry."""
    from unified_enforce import Action, ActionContext, Principal

    action = Action.build(
        principal=Principal(id="agent:claude-code"),
        tool="mcp://fs/read_file",
        verb="call",
        resource="*",
        params={"path": "/tmp/x"},
        context=ActionContext(origin="mcp", trace_id="0" * 31 + "1", span_id="0" * 15 + "1"),
    )
    resolver(telemetry, [Rule(tool="mcp://fs/*", effect="allow")]).resolve(
        "mcp://fs/read_file", {"path": "/tmp/x"}, "claude-code", action=action
    )
    (span,) = exporter.get_finished_spans()
    assert span.attributes["unified.action.digest"] == action.digest(strict=False)
    # ...and the decision hangs under the caller's trace, not a new one.
    assert format(span.context.trace_id, "032x") == action.context.trace_id


def test_no_telemetry_configured_is_a_silent_noop():
    """The default path must not require the [otel] extra or a collector."""
    r = resolver(None, [Rule(tool="mcp://fs/*", effect="allow")])
    assert r.resolve("mcp://fs/read_file", {}, "x").effect is Effect.ALLOW


def test_otel_is_off_by_default():
    assert _build_telemetry(OtelConfig()).enabled is False


def test_a_broken_collector_config_degrades_instead_of_failing_startup(monkeypatch):
    """Enforcement does not depend on being observed, so a bad endpoint must
    not stop the hub from serving tools."""
    import unified_mcphub.hub as hub_mod

    class Exploding:
        """Stands in for a missing [otel] extra or an unusable exporter."""

        def __init__(self, *args, **kwargs):
            raise RuntimeError("no exporter available")

        disabled = staticmethod(Telemetry.disabled)

    monkeypatch.setattr(hub_mod, "Telemetry", Exploding)
    built = _build_telemetry(OtelConfig(enabled=True, endpoint="http://127.0.0.1:1"))
    assert built.enabled is False
