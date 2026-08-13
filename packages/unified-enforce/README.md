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

## What "per agent" means

Policy is written against `principal.id`. Floors, budgets, deny rules and the
kill switch all key on it — so the strength of every rule is the strength of
that identifier, and every action now records **how it was established**:

| `attestation` | what it means |
|---|---|
| `assigned` | deployment position: a header a gateway stamped, a config value, a process boundary |
| `derived` | an authenticated channel: a bearer token the hub issued, a sidecar's enrolment credential |
| `attested` | a workload attestation — SPIFFE SVID, mTLS client certificate, cloud instance identity |

**Nothing produces `attested` yet.** The value exists so that adding it later is
a change of value rather than a change of shape, and so the distinction is
visible in the meantime rather than implied away.

**The honest phrasing today** is that the plane enforces per *deployment
position*. UAI-137 stopped an agent asserting its own identity, which is not the
same as establishing one. Two consequences worth stating rather than
discovering:

* **Several agents behind one sidecar share a principal.** They are
  indistinguishable to the plane, so per-agent policy is a fiction there and
  "revoke this agent" revokes all of them. One sidecar per agent is what makes
  per-agent policy mean what it says.
* **Per-agent policy is exactly as trustworthy as the customer's pod topology.**
  That is a defensible position. Pretending otherwise is not.

**Sub-agents carry lineage.** An agent that spawns agents is the common case,
and a child inheriting its parent's id makes the audit wrong in a way that only
surfaces during an incident. `parent_id` records the descent, and it is covered
by the action digest and by the evidence signature — but lineage is exactly as
trustworthy as the principal it descends from. A child of an `assigned` parent
is not better attested than its parent, and the two fields stay independent so
lineage cannot launder an unproven identity into a trusted-looking one.
