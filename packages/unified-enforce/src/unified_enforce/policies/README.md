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
| LLM10 | Unbounded Consumption | **Partial** | Per-action caps only. **No rate limiting or cumulative budgets** — see below. |

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

### LLM10: the gap, stated plainly

A per-action cap is enforceable. A **cumulative** budget is not, because the
engine is deliberately stateless — pure, sub-10 ms, no I/O on the decision
path. An agent held to $500 per refund can still issue a thousand of them.

The corpus asserts this as a **passing** case (`many-small-refunds-each-pass`,
`known_gap: true`) rather than describing it in prose. It stays visible in test
output, and when cumulative budgets land (UAI-147) the test fails and someone
has to change it deliberately.

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
