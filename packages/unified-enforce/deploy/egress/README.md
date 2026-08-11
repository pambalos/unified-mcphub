# Egress policy — the no-bypass guarantee

Envoy + ext_authz decides. **Egress policy is what makes that decision
unavoidable.** Without it, an agent can open its own socket and skip the plane
entirely, and enforcement degrades to best-effort — the thing the product
exists not to be.

The rule in every deployment mode is the same:

> The agent's network namespace / security group has **exactly one** allowed
> egress destination: the Envoy sidecar. DNS is the only other exception, and
> only to the platform resolver.

| Mode | Template | Mechanism |
|---|---|---|
| Kubernetes (VPC or SaaS) | `kubernetes-networkpolicy.yaml` | NetworkPolicy: deny-all egress + allow sidecar + DNS |
| VM / bare metal / air-gapped | `iptables-sidecar.sh` | Per-UID owner match: only the proxy UID may leave the box |
| AWS (EC2/ECS) | `aws-security-groups.tf` | Agent SG egress restricted to the proxy SG |

## Verifying it (do this before calling a deployment enforced)

1. From inside the agent container, `curl https://example.com` **must fail** —
   connection refused or timeout, not a 403 (a 403 means you reached Envoy,
   which is fine, but the direct-socket path must not even connect).
2. `curl` through the sidecar must return the engine's verdict headers
   (`x-unified-verdict`).
3. Kill the engine; traffic must **deny**, not pass (`failure_mode_allow:
   false`).
4. Check the audit chain: every attempt in steps 1–3 that reached Envoy has a
   decision entry (`unified-mcphub audit verify` / `AuditChain.verify`).

Step 1 is the one people skip. It is the only step that actually tests the
no-bypass property; the rest test enforcement.

## Air-gapped note

In zero-egress deployments the "allow sidecar" rule is the only egress rule at
all, and the upstream allowlist lives in policy (`match.tool` globs over
internal hosts). Nothing here requires outbound internet, including telemetry
(`otel.enabled` off by default, and Tempo/Langfuse are in-perimeter).
