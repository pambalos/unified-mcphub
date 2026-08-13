# unified-enforce

The Unified AI enforcement engine: every agent action is **canonicalized** into a
signed, replayable `Action`, **decided** deterministically against YAML+CEL policy
(`ALLOW` / `DENY` / `DEFER`), and **recorded** in an append-only, hash-chained audit
log.

Spec: `specs/enforce/e1.v1.md`. Product framing: `product.md` at the repo root.

```python
from unified_enforce import Action, Principal, PolicyEngine, AuditChain

engine = PolicyEngine.from_file("policy.yaml")
action = Action.build(
    principal=Principal(id="agent:claude-code"),
    tool="mcp://github/create_pr",
    verb="call",
    resource="repo:acme/api",
    params={"title": "fix"},
)
decision = engine.decide(action)   # deterministic, no I/O
chain = AuditChain(audit_dir)
chain.append_decision(action, decision)
```

- **Fail closed.** Unknown operators, condition errors, and missing rules never
  produce an accidental allow.
- **No network in the decision path.** Policy is compiled at load; `decide()` is
  pure compute.
- **Tamper-evident.** Each audit entry hashes its predecessor; `AuditChain.verify()`
  replays the chain offline.

## Deferred actions

`DEFER` means "a human decides this one". Without a consumer it is a deny with a
nicer label, so `Approvals` is that consumer and `RemoteApprovals` is the channel
that reaches a control plane:

```python
from unified_enforce import Approvals
from unified_enforce.remote_approvals import RemoteApprovals

channel = RemoteApprovals(
    "https://control.example",
    credential,                     # from enrolment
    fleet_id="acme",
    keys=distribution.verification_keys,   # rotates with the signed key set
)
outcome = await Approvals(channel, timeout_s=300).resolve(request)
```

**The answer is verified, not merely received.** A resolved approval releases an
action a policy floor deliberately held, so anything able to produce that JSON
could otherwise unblock it — and TLS does not close that: a mis-issued
certificate, an over-broad trust store, DNS takeover, or a TLS-terminating proxy
somebody added for observability all widen it again. Every response is checked
against `attest.accept_resolution`, which binds the decision to the action
digest, the fleet, an expiry, and the approver. **Any failure denies**, including
"cannot verify".

The resolution is recorded as its own chain entry beside the `DEFER` it answers,
carrying the attested approver and the signature. That is what makes "alice
approved the $12,400 refund" re-checkable years later by somebody who does not
trust whoever operates the control plane — a control plane's own queue table is
a queue, not evidence.
