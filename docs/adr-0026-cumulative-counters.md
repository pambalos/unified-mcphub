# ADR-0026 — Counting without putting state on the decision path

**Status:** accepted
**Ticket:** UAI-147, and it unblocks UAI-167 (deny-rate signal)

## The problem, stated precisely

`double(params.amount) <= 500.0` denies one oversized refund. It does not deny a
thousand refunds of $499, and every one of those is individually compliant. The
same shape appears three more times: rate limits, deny-rate as a rogue signal,
and novel-tool counts. All four need the same missing thing — the engine cannot
count.

It cannot count because `PolicyEngine.decide()` is a pure function with no I/O,
which is not an accident. It is what the <10 ms budget rests on, and it is what
makes the fail-closed story simple enough to be true: there is no lookup that
can hang, so there is no lookup that can be made to hang.

So the constraint is not "add state". It is: **add counting without adding a
lookup to the decision path.**

## What was rejected, and why

**An in-process counter the engine reads.** Fast, and it puts a mutable read
inside a function whose purity is load-bearing. Every test of `decide()` becomes
order-dependent, and the thing that made the engine auditable stops being true.
Rejected for what it does to the engine, not for what it does to correctness.

**Redis, or any shared store.** Correct across a fleet, and it puts a network
hop in a path measured at p99 8.38 ms. Worse, it forces a question with no good
answer: what does a budget check do when the store is unreachable? Fail closed
and one Redis outage stops every agent in the fleet. Fail open and the budget is
advisory — which is the fail-open this whole product exists to not have.

**Read the audit chain on each decision.** No new infrastructure, and it is a
file read per decision. The chain is the right *source* and the wrong *index*.

## The decision

Three parts, and the first is the one that matters.

### 1. Counters are an argument, not a lookup

`decide()` gains a parameter. The caller computes the totals and passes them in;
the engine reads them out of the CEL activation exactly like `params` or
`context`. It performs no I/O, holds no state, and stays a pure function of
`(policy, action, counters)` — still trivially testable, still with nothing on
the path that can block.

```yaml
- id: daily-refund-budget
  match: { tool: "sdk://payments/refund", verb: create }
  when: "spend.day + double(params.amount) <= 5000.0"
  effect: allow
```

This is the whole trick. "The engine cannot count" was never really about the
engine — a pure function can be handed a number. It was about where the number
comes from, and that is a question for the layer that already does I/O.

### 2. The counter is local, and survives a restart

`Enforcer` owns it: an in-process, bounded, time-windowed accumulator updated
after each decision. Sub-microsecond, no network, nothing to be unreachable.

It is per-sidecar, and that is a real limitation stated rather than papered
over: N sidecars enforcing a $5,000 daily budget will, in the worst case, permit
N × $5,000. See part 3.

**It is rebuilt from the audit chain at start-up**, which is not an optimisation
— it closes an attack. A counter that lives only in memory is a budget an agent
resets by crashing its own sidecar, and an agent that can spend $5,000 per
restart has no budget at all. The chain already records every decision with a
timestamp, so the totals for the current window are recoverable from a source
that is signed and append-only. Recovery reads it once, at boot, off the
decision path.

### 3. Fleet truth is the control plane's job, and it acts through containment

The sidecar enforces what it saw. The control plane already receives every
sidecar's decision stream through evidence ingest, so it is the only component
that can see a fleet total — and as of UAI-165 it already has an actuator for
acting on one: containment, with a measured 30-second bound.

So a fleet-wide budget is: sidecars enforce locally and immediately, the control
plane aggregates and contains the principal when the fleet total crosses. The
overspend window is bounded and stated — evidence lag plus one poll — rather
than hidden, and no part of the decision path acquired a dependency that can
fail.

This is the same division the rest of the design already uses: local decisions
that cannot be blocked, global corrections that arrive on a bound.

## What this costs, said plainly

- **Per-sidecar budgets over-permit by a factor of N** until the control plane
  catches up. A customer needing a hard fleet-wide cap needs one sidecar or the
  control plane's window, and the docs must say so rather than implying the
  local number is the fleet number.
- **A window of overspend is possible by design.** Bounded, measured, stated.
- **Counters recovered from the chain are only as complete as the chain.** A
  sidecar whose audit directory was wiped starts from zero, and that is the same
  trust boundary evidence already has: nothing downstream of a compromised
  writer can fix a writer that lied.

## What it costs on the decision path

Measured on the OWASP pack, 5,000 decisions after a warm-up, same machine:

    no counters                p50=0.4951ms  p99=0.9748ms
    2 counters + budget rule   p50=0.9357ms  p99=1.5651ms

Counting roughly doubles a very small number and stays six times inside the
10 ms budget. Almost all of the delta is the extra CEL evaluation — the budget
rule's condition and the counter's `value` expression — rather than the store,
which is a dict lookup and a bounded sum. This is the number the rejected
options were being compared against: a Redis round-trip on this path is
comparable to the entire budget, and it can also fail.

## How we will know it works

`many-small-refunds-each-pass` in `tests/corpus/owasp-llm-top10.yaml` is
currently a **passing** test marked `known_gap: true`, asserting `allow` so the
gap stays visible in test output. When cumulative budgets land, that case flips
to `deny` and the marker comes off. A gap that was declared as a test rather
than as prose is a gap that cannot be quietly forgotten — which is why it was
written that way, and it is now the acceptance criterion.
