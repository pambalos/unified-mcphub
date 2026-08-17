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

## What is automated

`iptables-sidecar.sh` is **executed** by
`tests/integration/test_egress_no_bypass.py`, which builds a two-container lab
(an agent host with the real script installed, and an "upstream" standing in
for a third-party tool) and asserts the guarantee end to end: the agent's TCP
lands on the sidecar instead of the upstream, QUIC and stray UDP are blocked,
DNS still resolves, the proxy uid is exempt, and a dead sidecar fails closed
rather than falling back to a direct connection.

The suite opens with a **negative control** — before the lock is installed the
agent *must* reach the upstream. Without it, a lab with no route to the
upstream would pass every subsequent assertion for the wrong reason.

That test immediately found a real defect in this script: `REDIRECT` rewrites
the destination to 127.0.0.1, but the packet reaches the filter chain still
carrying its original output interface, so the `-o lo` RETURN matched nothing
and the catch-all DROP ate every redirected connection. Fail-closed, but the
agent could reach neither the upstream nor its own sidecar. Fixed by matching
on the loopback *destination*; pinned by a test that asserts the DROP counter
does not move.

The Terraform is structurally checked (`test_egress_manifests.py` runs
`terraform validate`) and its enforcement is proven by observation in a real
AWS account by `deploy/test-harness` — two instances in one subnet, security
group the only difference.

The NetworkPolicy is structurally checked the same way (it really declares
`Egress` in `policyTypes` — omitting it silently restricts nothing — and
permits DNS), and **cluster-proven** by
`verify-kubernetes-networkpolicy.sh`: it applies the shipped manifest
verbatim to a real cluster and measures the differentials — a label-free
CONTROL pod that must reach both the internet and the in-cluster upstream
(so a broken network cannot masquerade as enforcement), an enforced agent
pod for which only DNS survives, and a sidecar pod that reaches exactly the
allowlisted namespace and nothing else. First proven 2026-08-17 on minikube
+ Calico (7/7), cluster created for the run and deleted after. The script
needs any cluster whose CNI enforces NetworkPolicy — Calico, Cilium, k3s'
default; **not** kind's default kindnet, where the manifest is decoration
and the script will say so by failing.

## Air-gapped note

In zero-egress deployments the "allow sidecar" rule is the only egress rule at
all, and the upstream allowlist lives in policy (`match.tool` globs over
internal hosts). Nothing here requires outbound internet, including telemetry
(`otel.enabled` off by default, and Tempo/Langfuse are in-perimeter).
