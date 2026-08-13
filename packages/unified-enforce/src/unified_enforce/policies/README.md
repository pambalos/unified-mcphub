# Policy packs

Starter policies mapped to recognised AI-security frameworks, with an
adversarial corpus proving each rule blocks what it claims
(`tests/unit/test_policy_packs.py`).

These are **reference policies, not drop-ins.** Tool URIs and thresholds are
examples. What is meant to survive copying is the shape: which categories an
enforcement plane can act on, and how each rule is written.

## OWASP Top 10 for LLM Applications (2025)

The honest coverage matrix. A pack claiming all ten would be worse than useless
to a security team, because the first category they probed would expose the
rest as marketing.

| | Category | Coverage | What we actually do |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | **Contained** | We do not detect injection. Floors ensure a *successful* injection still cannot complete a damaging action unsupervised. |
| LLM02 | Sensitive Info Disclosure | **Partial** | We govern which sinks data may reach and what the audit retains. We cannot inspect model output. |
| LLM03 | Supply Chain | ✗ | Model and package provenance. The hub pins versions; the engine has no view. |
| LLM04 | Data & Model Poisoning | ✗ | Training-time. Different layer entirely. |
| LLM05 | Improper Output Handling | ✗ | Downstream of the tool call we gate. |
| LLM06 | **Excessive Agency** | **Full** | The category this product exists for: tool allowlists, value-level authority, destructive-action floors, human approval. |
| LLM07 | System Prompt Leakage | ✗ | Inside the model context; we never see it. |
| LLM08 | Vector/Embedding Weaknesses | ✗ | Retrieval layer. |
| LLM09 | Misinformation | ✗ | Model output quality. |
| LLM10 | Unbounded Consumption | **Partial** | Per-action caps and cumulative budgets. Totals are **per sidecar** — see below. |

Four of ten are genuinely other layers' problems, and saying so is the point.
An enforcement plane sits at the tool call; categories that live in the prompt,
the training set, or the response are not ours to claim.

### LLM01: contained, not detected

We make no claim to detect prompt injection, and the pack does not try. The
claim we do make is narrower and holds under adversarial pressure: **a
successful injection still cannot call a forbidden tool.** Detection is a
classifier that degrades as attacks evolve; containment is architectural.

The corpus reflects this. Cases like `injected-shell-command` assert that the
*action an injection would produce* is stopped — not that we noticed the
injection. `injected-egress-lock-removal` is the sharpest of them: an agent
persuaded to edit infrastructure could remove its own egress lock and escape
the plane, so that operation floors to a human.

E5 (taint propagation and intent binding) will strengthen this by catching an
injection's *effect* through data flow, which is enforcement rather than
detection.

### LLM10: what is enforced, and the boundary that remains

Per-action caps and **cumulative budgets** both work now (UAI-147). An agent
held to $500 per refund can no longer issue a thousand of them: the pack
declares a `refund_spend` counter and `llm10-daily-refund-budget` reads it.

The engine is still stateless. Totals are computed by the enforcer and handed
to `decide()` as data, so the decision path acquired no I/O and no lookup that
can hang — see `docs/adr-0026-cumulative-counters.md`, which is worth reading
before writing a counter of your own.

**The total is what one sidecar saw.** Ten sidecars enforcing a $5,000 day can
permit $50,000 before the control plane's fleet view catches up and contains the
principal (on a measured 30-second bound). That is a bounded window, not an
unenforced budget, and the corpus asserts it as a **passing** case —
`a-budget-is-per-sidecar-not-per-fleet`, `known_gap: true`, running the sequence
across two independent enforcers. Its predecessor
(`many-small-refunds-each-pass`) was the same kind of declared gap and now
expects `deny`, which is exactly what a gap declared as a test is for.

Two things to copy when writing your own counter:

- **Count allows, not attempts.** `on_verdict: allow` — a refund that was denied
  did not spend anything, and counting it lets a blocked agent exhaust its own
  budget by being blocked.
- **Scope the budget rule to actions that are otherwise permitted.** The rule
  here checks `double(params.amount) <= 500.0` as well as the day total,
  because without it a single $10,000 refund is denied outright instead of
  going to the human review a floor already demanded. A cumulative budget
  answers a question about a *sequence*; it should not quietly remove an
  escalation path.
- **`on_verdict`, not `on`.** YAML 1.1 reads a bare `on` as boolean true, which
  is why the field is not called that.

## The external check

The corpus above is written by whoever wrote the pack, which makes it excellent
at catching regressions and poor at catching blind spots. `benchmarks/external.py`
runs suites we did not author — InjecAgent today, AgentDojo declared and not yet
implemented — nightly.

**They measure a different thing, and the adapter knows it.** Those benchmarks
mostly score whether a *model* resists an injection. We score whether the
*plane* stops the resulting tool call, so the model is never run: what is
extracted is the tool call the attack was trying to cause.

The report separates a named rule denying something from **default-deny**,
because the packs use their own example tool URIs and an unmapped benchmark tool
is refused by the non-configurable default. Counting that as a win would produce
a triumphant number describing a pack that recognised nothing.

Latest run, 1,598 attacker tool calls from InjecAgent:

    denied by a rule   612   <- the score
    deferred           136
    denied by default  816   (true, and not a defence)
    ALLOWED             34   <- findings

    stopped by policy: 46.8%

Unflattering on purpose. The 34 that got through collapse to two shapes, both
MCP reads, and both are now authored corpus cases — which is the rule: every
attack that gets through becomes a case, so the fast suite grows from what the
slow one finds.

## Two things that will bite you writing your own

Both were bugs in this pack within an hour of writing it. Both are now load
errors or tested.

**Order is semantics.** Within a precedence tier it is first-match-wins, so a
deny written after a broader allow never runs. The first draft had
`mcp://vault/get_secret` matching a broad read allow before reaching the
credential deny — a security rule that was simply never reached.

**No brace expansion.** `mcp://{iam,secrets,vault}/**` does not mean what it
looks like; it used to compile as literal characters and match nothing, for
ever. This is now a **load error**, because a dead allow is annoying while a
dead deny is a control that was never there and looks identical to one that
works. Write one rule per alternative.

## Other frameworks

**EU AI Act** and **NIST AI RMF** are governance frameworks rather than rule
sets — they ask whether you can demonstrate control and produce evidence, which
is answered by the hash-chained audit log (E2) and replay, not by a policy
file. Compliance *reports* derived from that evidence are C2.

**MITRE ATLAS** techniques map largely onto LLM01/LLM06 here; a dedicated pack
is worth writing once a design partner asks in those terms.

## Using a pack

```python
from unified_enforce import PolicyEngine
engine = PolicyEngine.from_file("policies/owasp-llm-top10.yaml")
```

Copy it, replace the tool URIs with yours, and keep the corpus habit: for every
rule you add, add the attack it blocks *and* the legitimate call it must not.
A pack that denies everything passes every attack test.
