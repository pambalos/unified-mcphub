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

## Hub emission (UAI-86)

The engine's spans were unused for their first iteration: the hub drove the
policy engine directly, so the one product actually running the enforcement
plane produced no traces. `AuthzResolver` now decides through an `Enforcer`
carrying the hub's `Telemetry`, configured by `hub.otel` (off by default,
non-breaking when off, `[otel]` extra not required to run).

No audit chain is attached to that Enforcer. The hub keeps its own two-phase
`AuditLog` — already chained since the E2 migration — because it records the
*completion* half of a call, which the engine's single-entry decision form
cannot express.

One defect surfaced in the wiring and is worth remembering: `record_decision`
computed a **strict** action digest, and MCP tool arguments are free-form JSON
that may contain floats, which strict canonicalization refuses. Enabling
telemetry would have raised on the hot path of any call carrying a float. The
span digest is now computed leniently — it is a *correlation key*, meant to
join a span to the audit entry for the same action, not evidence, and the hub's
audit writes `strict=False` digests, so a strict one would both crash and fail
to match the entry it points at. Wherever strict succeeds the bytes are
identical, so nothing else changes.

Telemetry construction degrades to the no-op on failure and logs: enforcement
does not depend on being observed, and a bad collector endpoint must not stop
the hub from serving tools.

## Out of scope here

The `unified-collector` daemon, embedded Tempo store, log-tail bridges, and the
Grafana bundle remain the rest of the M0.5 Observability milestone — this spec
covers the engine's emission seam and the hub's use of it.
