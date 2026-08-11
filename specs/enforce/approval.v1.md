# Approval contract — the DEFER consumer

Status: **implemented** (`unified_enforce/approval.py`). Linear UAI-133.
Supersedes the hub-local approval logic described in mcphub spec §5 / ADR-0018 /
ADR-0025, which is now an adapter over this.

## §1 Why this exists

DEFER is the verdict that says *a human decides this one*. Until now only the
hub could act on it. Everywhere else — the gateway, the SDK — DEFER was a deny
with a nicer label, and each new surface would have re-implemented the
security-critical parts: the master switch, the session cache, and the handling
of every way that asking a human fails.

That re-implementation is exactly where a fail-open gets introduced. So the
contract moves into the engine, and the surfaces keep only their vocabulary.

## §2 The split

`ApprovalChannel` is **only** a way to reach a human: `ask(request)`, return
what they said. It is deliberately incapable of deciding anything.

`Approvals` owns everything that can go wrong on the way. A channel that cannot
reach anyone raises, and `Approvals` turns that into a deny — a new channel
cannot introduce a fail-open path because it has no say in the matter.

| condition | verdict | `Decision.source` |
| --- | --- | --- |
| human allows | ALLOW | `approval` |
| human denies | DENY | `approval` |
| session grant hit | ALLOW | `approval_session` |
| no channel configured | DENY | `approval_unavailable` |
| channel raised | DENY | `approval_error` |
| nobody answered in time | DENY | `approval_timeout` |
| approvals disabled | DENY (default) | `approval_disabled` |

A deferred action is one that policy has already declined to allow on its own.
Being unable to ask about it is not a reason to proceed. `asyncio.CancelledError`
is the one exception that propagates rather than becoming a verdict: process
shutdown is not a decision about the action.

**`when_disabled="allow"` is the only fail-open in the design, and it is not
the default.** It exists because the hub's `approval.enabled: false` master
switch (ADR-0018) means "don't prompt, run it" — a deliberate local-development
affordance its e2e matrix depends on. Any deployment wanting that has to ask for
it in writing.

## §3 What the engine will not do

**It does not write policy.** `ALLOW_ALWAYS` / `DENY_ALWAYS` surface as
`outcome.persistent` plus the scope filter; persisting is the caller's job,
because where rules live is a property of the deployment (a hub workspace file,
a control-plane API) rather than of the decision.

**It does not own the human-facing vocabulary.** The hub keeps its own
`DecisionKind` — its two allow-always variants (exact command vs. prefix) are
part of the control API's wire format, and they differ only in how the scope
filter was built, which the filter itself records. One engine kind, two hub
kinds, no information lost.

## §4 Recording

A resolved deferral is chained as its **own** entry (`kind: "approval"`), joined
to the decision entry by `action_digest`.

Not a rewrite of the DEFER, for two reasons. The chain is append-only, so the
earlier entry stands regardless. And more importantly: that review was demanded,
and that a named human resolved it, are two separate events. An evidence log
that collapses them cannot answer *who approved this?* — which is the question
the log exists to answer.

`elapsed_us` is an integer, matching the decision entry: floats are refused by
strict canonicalization, and how long a person took is not worth a non-portable
digest.

## §5 Consumers

**Hub** — `Approval` is now an adapter. It translates its `DecisionKind` and
`PromptOutcome` in and out, and passes the canonical Action the verdict was
already made on. Behaviour is unchanged and pinned by the existing suite,
*except* that a channel which raises is now a clean deny rather than an
exception escaping into the call path — a 500 where a refusal belongs. The
module used to promise this as "later phases"; this is that phase.

**SDK** — `check_async()` and the async `@action` decorator route DEFER through
approvals. `check()` stays synchronous and never blocks: asking a person is a
fundamentally different operation from evaluating policy, and code on a request
path with a timeout should keep using `check()` and treat DEFER as a refusal.

**Gateway** — unchanged, and deliberately. A synchronous HTTP call cannot wait
for a human without hanging an Envoy worker, so gateway DEFER stays a 403 with
`x-unified-verdict: defer`. The asymmetry is the point: approvals apply to a
subsequent retry, not to the call in flight.

With no approvals configured, `Enforcer.enforce_with_approval()` returns the
DEFER **unchanged** rather than synthesizing a deny. A missing approval channel
should look like a missing approval channel, not like policy.

## §6 Verification

`tests/unit/test_enforce_approval.py` — 22 tests, most of them about the paths
where asking a human does *not* work, since that is where a fail-open would
hide: no channel, a raising channel, a silent channel, cancellation, the master
switch in both positions, session scoping and expiry, and the end-to-end
Enforcer flow asserting both chain entries and their digest join.
