# unified-sdk

Annotate agent actions with business semantics, so policy can reason about what
an operation *means* — not just where it goes.

**The proxy is the lock; the SDK is the label.**

A network sidecar sees `POST https://api.stripe.com/v1/refunds`. It can enforce
"no POST to /v1/refunds". It cannot enforce "no refund over $5,000", because
nothing at the network layer knows what a refund is. This package closes that
gap.

```python
from decimal import Decimal
from unified_sdk import UnifiedAI, Denied

ua = UnifiedAI.local("policy.yaml", principal="agent:crew-1",
                     audit_dir="~/.unified/audit")

@ua.action("stripe://refunds", verb="create",
           resource="customer:{customer_id}", params=["amount"])
def issue_refund(customer_id: str, amount: Decimal) -> None:
    stripe.Refund.create(customer=customer_id, amount=amount)

try:
    issue_refund("42", Decimal("8000.00"))
except Denied as exc:
    log.warning("blocked by %s (action %s)", exc.decision.rule_id, exc.digest)
```

with the matching rule:

```yaml
version: 1
rules:
  - id: small-refunds
    match: {principal: "agent:crew-*", tool: "stripe://refunds", verb: create}
    when: 'double(params.amount) <= 5000.0'
    effect: allow
```

## It is optional, and that is the point

An application that never calls this package is **still enforced** at the
network layer by the gateway (`unified-enforce`, E3). The SDK raises the
*resolution* of policy; it is not what makes enforcement happen. If skipping it
granted more freedom, every agent would skip it.

The corollary matters when you write rules: annotations are **claims made by
the application**, which sits inside the trust boundary the gateway protects.
Use them to *narrow* what the network layer already allows — never to widen it.
Policy can tell them apart via `context.origin`.

## Three call styles

```python
# Decide and branch — never raises.
act = ua.check("stripe://refunds", verb="create", params={"amount": 100})
if not act.allowed:
    return offer_manual_review()

# Guard a block — decides first, so a denied operation never starts.
with ua.acting("stripe://refunds", verb="create",
               resource="customer:42", params={"amount": "8000.00"}) as act:
    httpx.post(url, json=payload, headers=act.headers)

# Decorate — templates over the function's own arguments.
@ua.action("stripe://refunds", verb="create", params=["amount"])
async def issue_refund(amount): ...
```

`async def` is handled properly: the guard wraps the awaited call, not just the
coroutine's creation.

## Two behaviours worth knowing

**Capture is explicit.** `params=["amount"]` names exactly what policy needs.
Nothing else is captured, because sweeping every argument into an audit chain
is how API keys and personal data end up in an evidence log.

**Amounts become strings.** `float` and `Decimal` are normalized to text
(`Decimal("4999.99")` → `"4999.99"`). Floats have no portable repr, so a signed
action carrying one would not verify on a non-Python verifier — and this
matches what the gateway produces for the same payload, so both observations of
one operation canonicalize identically. Compare with `double(params.amount)` in
CEL.

## Correlating with the gateway

`act.headers` carries `x-unified-action: <digest>` (and `traceparent` when
tracing is configured). Attach it to the outbound call and the sidecar records
that its network-level observation and your semantic action are the same
operation — joinable in the audit chain.

It is recorded as a **claim** and never trusted: a forged value cannot change a
verdict, and the sidecar strips the header before the request reaches the
upstream. Omitting it costs nothing but the link.

## Install

```bash
pip install unified-sdk        # brings in unified-enforce
```

Spec: [`specs/enforce/e4.v1.md`](../../specs/enforce/e4.v1.md).
