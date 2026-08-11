# Engine observability — OTel decision spans

Status: implemented (v0.0.1). Linear: UAI-116, milestone M0.5 · Observability
Stack. Stack decision: technologies.md (Telemetry row — OTLP-pluggable backend,
embedded Tempo default).

## Design (`telemetry.py`, `enforcer.py`)

- One span per decision: `enforce.decide <tool>`, emitted **after** the verdict —
  telemetry is never inside the <10 ms policy path, and `decide()` itself stays
  pure. `Enforcer` composes decide → audit chain → span; an audit failure still
  emits the span (evidence survives) and then raises (an unrecorded ALLOW is a
  hole in the record).
- **Off by default, zero hard deps.** `Telemetry.disabled()` is a no-op;
  OpenTelemetry packages are imported only when enabled and live behind the
  `unified-enforce[otel]` extra.
- **Backend-pluggable via OTLP/HTTP.** Endpoint + headers config reaches Tempo,
  any collector, or Langfuse. `Telemetry.for_langfuse(host, public_key,
  secret_key)` derives the `/api/public/otel/v1/traces` endpoint and Basic-auth
  header for self-hosted or cloud Langfuse.
- **Trace continuity.** When `Action.context.trace_id`/`span_id` are set (hex
  OTel ids propagated by the intercepted framework), the decision span is
  parented remotely under them — a DENY renders inline in the trace the agent
  started. Malformed ids never break emission (span falls back to a new root).

## Attributes

`unified.action.id`, `unified.action.digest`, `unified.principal.id`,
`unified.principal.kind`, `unified.tool`, `unified.verb`, `unified.resource`,
`unified.verdict`, `unified.decision.source`, `unified.policy.audit_level`,
plus `unified.rule_id` / `unified.reason` when present.

Langfuse rendering: `langfuse.observation.level` — ALLOW → `DEFAULT`,
DENY / DEFER → `WARNING` (blocked is signal, not failure),
`condition_error` → `ERROR` (broken policy is failure).

## Out of scope here

The `unified-collector` daemon, embedded Tempo store, log-tail bridges, and the
Grafana bundle remain the rest of the M0.5 Observability milestone — this spec
covers only the engine's emission seam.
