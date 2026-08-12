# Deployment-mode Terraform

The three modes from the one-pager, as infrastructure. One shared module and
three example root modules that differ only in **what egress they permit** —
because that difference *is* the deployment mode.

| Mode | Sidecar reaches | Egress to us | Use |
| --- | --- | --- | --- |
| `self-hosted` | in-perimeter upstreams only | **none** | Air-gapped, defence, critical infrastructure |
| `byoc` | an allowlist of external tools | **none** | Customer VPC; data never leaves the account |
| `hybrid` | allowlisted tools | one CIDR set, one port | Hosted control plane: policy down, evidence up |

```
modules/dataplane-aws/    the security-group topology (the reusable part)
examples/self-hosted/     air-gapped
examples/byoc/            customer VPC
examples/hybrid/          customer VPC + hosted control plane
```

## What this provisions, and what it does not

**Does:** the network topology that makes enforcement unavoidable. The agent
workload may reach exactly one destination — the sidecar — plus DNS. The
sidecar reaches an allowlist. Nothing else leaves.

**Does not: compute.** Whether the agent is an ECS task, an EC2 instance or a
pod varies more between adopters than it shares, so the module outputs security
group ids for your launch template or task definition to attach. A module that
created the compute too would be rewritten by everyone who used it.

**Does not: the control plane.** `unified-control-plane` (C1) does not exist
yet. The hybrid example opens the *seam* — a narrow, explicit egress rule — and
stops there. Terraform that stood up a service we have not built would be
fiction; when C1 lands it gets its own module and this one keeps working.

## The property hybrid mode rests on

**Decisions stay local.** The engine evaluates policy in-process, in your VPC,
on the sub-10 ms path. The control plane distributes policy and receives
evidence, asynchronously. Cut the link to us and the agent keeps being enforced
against its last-known policy — it does not fail open, and it does not stall.

That is why the control-plane egress belongs to the **sidecar**, never the
agent: an agent that could reach the control plane directly could try to
influence its own policy. The agent's reachability is identical in all three
modes.

## Single-host deployments

Security groups do not filter loopback. Where the agent and sidecar share a
network namespace, this module is the wrong tool — use
[`iptables-sidecar.sh`](../../packages/unified-enforce/deploy/egress/), which is
executed for real by `tests/integration/test_egress_no_bypass.py`.

## Verification

```bash
terraform -chdir=examples/byoc init -backend=false && \
terraform -chdir=examples/byoc validate
```

`tests/integration/test_terraform_modules.py` discovers every `.tf` directory
and validates it, checks formatting, and asserts the postures: the air-gapped
example opens no path to us, every example carries a `check` block, and no
module grants `0.0.0.0/0`.

Be clear-eyed about what that buys. `validate` checks syntax, provider schema
and wiring; it never contacts AWS and cannot tell you traffic is blocked. The
`check` blocks are better — they fail a *plan* when a mode loses its posture —
but proof of enforcement still needs a real account, which is G2 work.

After `apply`, confirm the thing most likely to be silently wrong:

```bash
aws ec2 describe-security-groups --group-ids <agent-sg> \
  --query 'SecurityGroups[0].IpPermissionsEgress'
```

AWS attaches an allow-all egress rule to every new security group. Terraform
removes it when the group is declared without an inline `egress` block, as
these are — but an `0.0.0.0/0` entry on the agent group means there is no
no-bypass guarantee, whatever the plan said.
