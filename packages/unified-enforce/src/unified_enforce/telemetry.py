"""OTel decision spans — UAI-116, M0.5 Observability.

One span per decision (`enforce.decide <tool>`), emitted *after* the verdict —
telemetry is never in the <10 ms policy path. Off by default: the disabled
telemetry object is a no-op and the OpenTelemetry packages are only imported
when telemetry is enabled (they live behind the `unified-enforce[otel]` extra).

The backend is pluggable via standard OTLP: embedded Tempo is the product
default (technologies.md), but any OTLP/HTTP collector works — including
Langfuse's `/api/public/otel` ingest, for which `for_langfuse()` builds the
Basic-auth exporter. When the intercepted framework already carries a trace
(`Action.context.trace_id`/`span_id`), the decision span is parented under it,
so a DENY shows up inline in the trace the agent started.
"""

from __future__ import annotations

import base64
import time
from typing import Any

from .action import Action
from .policy import Decision, Verdict

_INSTALL_HINT = "OpenTelemetry packages are not installed — pip install 'unified-enforce[otel]'"


# Langfuse observation levels: DEBUG | DEFAULT | WARNING | ERROR.
# A blocked or deferred action is signal, not failure; a broken condition is failure.
def _langfuse_level(decision: Decision) -> str:
    if decision.source == "condition_error":
        return "ERROR"
    if decision.verdict in (Verdict.DENY, Verdict.DEFER):
        return "WARNING"
    return "DEFAULT"


class Telemetry:
    """Emit decision spans over OTLP. Construct disabled() for the no-op."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        service_name: str = "unified-enforce",
        endpoint: str | None = None,
        headers: dict[str, str] | None = None,
        exporter: Any | None = None,  # injected SpanExporter (tests); overrides endpoint
    ) -> None:
        self._provider = None
        self._tracer = None
        if not enabled:
            return
        try:
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
        except ImportError as exc:
            raise RuntimeError(_INSTALL_HINT) from exc

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        if exporter is not None:
            provider.add_span_processor(SimpleSpanProcessor(exporter))
        else:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )
            except ImportError as exc:
                raise RuntimeError(_INSTALL_HINT) from exc
            provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, headers=headers or {}))
            )
        self._provider = provider
        self._tracer = provider.get_tracer("unified_enforce")

    @classmethod
    def disabled(cls) -> "Telemetry":
        return cls(enabled=False)

    @classmethod
    def for_langfuse(
        cls,
        host: str,
        public_key: str,
        secret_key: str,
        *,
        service_name: str = "unified-enforce",
    ) -> "Telemetry":
        """Point spans at a Langfuse instance (self-hosted or cloud).

        `host` is the Langfuse base URL (e.g. https://langfuse.internal); the
        OTLP traces path and Basic-auth header are derived from it.
        """
        auth = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode("ascii")
        return cls(
            service_name=service_name,
            endpoint=host.rstrip("/") + "/api/public/otel/v1/traces",
            headers={"Authorization": f"Basic {auth}"},
        )

    @property
    def enabled(self) -> bool:
        return self._tracer is not None

    # --- emission ---

    def record_decision(self, action: Action, decision: Decision) -> None:
        if self._tracer is None:
            return
        from opentelemetry.trace import (
            NonRecordingSpan,
            SpanContext,
            TraceFlags,
            set_span_in_context,
        )

        end_ns = time.time_ns()
        start_ns = end_ns - int(decision.elapsed_ms * 1_000_000)

        context = None
        tid, sid = action.context.trace_id, action.context.span_id
        if tid and sid:
            try:
                parent = SpanContext(
                    trace_id=int(tid, 16),
                    span_id=int(sid, 16),
                    is_remote=True,
                    trace_flags=TraceFlags(TraceFlags.SAMPLED),
                )
                context = set_span_in_context(NonRecordingSpan(parent))
            except ValueError:
                context = None  # malformed ids from the caller never break emission

        attributes: dict[str, Any] = {
            "unified.action.id": action.id,
            "unified.action.digest": action.digest(),
            "unified.principal.id": action.principal.id,
            "unified.principal.kind": action.principal.kind,
            "unified.tool": action.tool,
            "unified.verb": action.verb,
            "unified.resource": action.resource,
            "unified.verdict": decision.verdict.value,
            "unified.decision.source": decision.source,
            "unified.policy.audit_level": decision.audit_level,
            "langfuse.observation.level": _langfuse_level(decision),
        }
        if decision.rule_id is not None:
            attributes["unified.rule_id"] = decision.rule_id
        if decision.reason is not None:
            attributes["unified.reason"] = decision.reason

        span = self._tracer.start_span(
            f"enforce.decide {action.tool}",
            context=context,
            start_time=start_ns,
            attributes=attributes,
        )
        span.end(end_time=end_ns)

    def shutdown(self) -> None:
        """Flush pending spans (BatchSpanProcessor) and release the provider."""
        if self._provider is not None:
            self._provider.shutdown()
            self._provider = None
            self._tracer = None
