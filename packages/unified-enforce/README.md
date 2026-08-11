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
