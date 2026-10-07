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

The approval entry carries the DEFER's `policy_digest`, so *against which policy
was a human asked?* is answered by the approval entry alone.

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

A **joined hub** (`control_plane.approvals: console`, the default once a
`control_plane:` block is set) installs `RemoteApprovals` beneath this adapter
as an engine-level channel (`fleet.ConsoleApprovals`, bound to the fleet
credential at start; unbound it raises, so every prompt denies). The request
carries the real deferring decision — the readable rule id and the policy
digest — and the same canonical Action the verdict was made on. The outcome's
attested approver and signed resolution are written into the hub's `received`
entry (`approver`, `attestation`, and `resolution: {kind, scope}` — the rest of what
the signature covers, so the entry can be re-verified offline; `decided_by` is
the approver's subject). An
`allow_always` from the console with no scope is honoured for the call and not
persisted: whole-tool trust is curated policy (ADR-0025), and a remote click
must not accrete it into the hub's `.local.yaml`. `approvals: terminal` keeps
the local channels exactly as before.

**What a queued approval shows the approver** (`RemoteApprovals._queue`). The
control plane keys the queue on `action_digest` and the decision key signs that
digest; it does not recompute the digest from the posted action, and the
reporter verifies the signed resolution against the digest *it* computed. So
the posted action is for display, and content can be withheld from it without
weakening the binding:

- `context.extra` is never sent (integration bookkeeping, not what the agent
  asked to do — payload evidence excludes it for the same reason).
- `params` are withheld, and the `summary` replaced with
  `<tool> (arguments withheld: <reason>)`, when the deferring rule is
  `audit_level: minimal` (`audit_level_minimal`) or the deployment said no
  content leaves (`share_params=False`; the hub's `control_plane.payloads:
  off` → `payloads_off`), or the DEFER was forced by distribution state
  (`approval.gate_forced`: an unknown or stale revocation list, an expired
  bundle under `on_stale: defer`, a `defer` containment, including when the
  engine also deferred → `distribution_state`). The body then carries
  `params_withheld: <reason>`.
  The approver decides on the tool, principal, rule and reason, and is told
  the arguments were withheld. Otherwise approvers *do* see the arguments —
  deciding whether `rm -rf build/` may run needs the command — so a console
  approval is a copy of that content to the control plane, and follows the
  payload stream's transport rule: a hub refuses console approvals to a
  control plane that is not `https://` (loopback `http://` excepted), denying
  every prompt and reporting `fleet.approvals_disabled: insecure_transport`.
- The body also carries `deadline_seconds` (how long the reporter will wait, so
  the control plane can expire the item; advisory there) and
  `decision.policy_digest`. Both are optional; an older control plane ignores
  them. `deadline_seconds` is sent as an integer, rounded up from the
  configured deadline, for control planes that validate an int.

Nothing is queued while the reporter holds no verified decision key (no key
set has verified yet — an un-polled or unprovisioned reporter — or the last
one stopped verifying): `RemoteApprovals.ask` raises `NoVerificationKeys`
before posting, and the prompt is denied (`approval_error`). Queueing would
put a question in front of an approver whose answer is certain to be refused.

A deadline that passes with no answer raises `ApprovalTimeout` (a
`TimeoutError`) and is recorded as `approval_timeout` / `approval_timed_out`,
not as a channel error.

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
