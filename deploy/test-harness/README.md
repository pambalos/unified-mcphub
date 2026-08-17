# Deployment-mode test harness (UAI-161)

Stands the deployment modes up in a real AWS account and asserts the properties
they exist to hold. `terraform validate` proves the HCL parses; this proves the
security groups stop traffic.

```bash
eval "$(deploy/test-harness/assume.sh)"          # temporary, scoped credentials
cd deploy/test-harness
terraform apply -var "ami_id=$(cat .ami-id)"                        # free
terraform apply -var "ami_id=$(cat .ami-id)" -var with_instances=true  # ~1¢
./observe.sh
terraform destroy -var "ami_id=$(cat .ami-id)"
```

## The mistake this harness is designed around

The obvious way to test "an air-gapped deployment reaches nothing" is to build a
VPC with no internet gateway and observe that nothing gets out.

**That proves nothing.** With no route to the internet, traffic fails whether or
not the security groups exist — the test passes identically with them deleted.
It measures the absence of a route.

So there are two VPCs, and the enforcement assertions run in the *connected* one:

| VPC | CIDR | internet | what it answers |
|---|---|---|---|
| `unified-test-connected` | `10.20.0.0/16` | IGW, public subnet | does the **security group** stop egress when egress is otherwise available |
| `unified-test-isolated` | `10.30.0.0/16` | none | does the stack **function** with no connectivity at all |

And the connected VPC runs **two** instances in the same subnet: the one under
test, and a control on the default security group. Without the control, "blocked"
is indistinguishable from "the network is broken".

## Result of the first real run — 2026-08-14

```
CONTROL  (default SG)        egress-REACHED https://example.com
                             egress-REACHED https://api.github.com
                             imds-reached

AIRGAP   (self-hosted SGs)   egress-blocked https://example.com
                             egress-blocked https://api.github.com
                             imds-reached          <-- finding
```

Same subnet, same internet gateway, same AMI. The only difference is the
security group, and it is what stopped the traffic. That is an air gap verified
by observation.

### The finding: IMDS is not covered by the air gap

Both instances reached `169.254.169.254`. Link-local addresses are not governed
by security-group egress rules, so **the self-hosted mode's "nothing leaves the
perimeter" claim does not extend to the instance metadata service** — which on an
instance with a profile attached is a credential endpoint reachable by anything
that can make an HTTP request from that host, including a compromised MCP server.

This is exactly the kind of gap a configuration review does not produce, and it
is why the ticket asked for observation. Mitigations are outside the security
group: `http_endpoint = "disabled"` where the workload does not need it, or
IMDSv2 with `http_put_response_hop_limit = 1`, which stops a container reaching
it.

### The remediation (2026-08-17)

Shipped and folded back into the harness. The airgap probe now launches with
`http_tokens = "required"` and `http_put_response_hop_limit = 1`, and the
probe measures both halves: tokenless IMDSv1 must refuse on the hardened
instance, and the host must still mint an IMDSv2 token — cloud-init fetched
the probe script through that path, so a mitigation that kills it kills the
boot contract. `observe.sh` additionally reads the applied `MetadataOptions`
back from the EC2 API, because the hop limit itself cannot be measured from a
bare host: it constrains the response crossing a routed hop, and the probe
carries no container runtime.

The verification run (2026-08-17) sharpened the original finding. Tokenless
v1 refused on the **control** too: AL2023 AMIs default to tokens-required, so
the 08-14 `imds-reached` was a 401 answering, not credentials moving. What
the Terraform actually adds on such AMIs is the hop limit — the AMI default
is 2, which is precisely one routed hop, i.e. a container reaches it — and
the fact that both settings are pinned in configuration rather than inherited
from an AMI default that a different image choice would silently lose. The
liveness baseline in `observe.sh` is therefore the control's token mint, not
tokenless v1.

Full `http_endpoint = "disabled"` remains the stronger setting where the
workload does not boot by user_data and holds no role; the dataplane module
exports the required settings as `required_metadata_options` so customer
launch templates attach them alongside the security groups.

What hop limit 1 does **not** cover, stated so nobody oversells it: an MCP
server running as a plain host process shares the host's network namespace and
can still mint tokens. On such hosts the answer is no instance profile, or no
IMDS. The containerised-upstreams work (M0.5, SEC-MCP-5) is what moves MCP
servers behind the hop.

## Cost

VPCs, subnets, gateways, route tables and security groups are free. Two
`t4g.nano` instances for the length of a run are a fraction of a cent. There is
deliberately **no NAT gateway** (~$0.045/hr, and the only thing here that would
cost real money): the probe sits in a public subnet, which is cheaper *and* a
stronger test, because egress is maximally available and the security group is
the only thing in the way.

Getting results out of the isolated VPC without internet: no SSM interface
endpoints (~$0.01/hr each, three needed). The probe writes to the serial console
from user-data, read back with `ec2:GetConsoleOutput`, which costs nothing.

## Credentials

`assume.sh` mints one-hour credentials for
`arn:aws:iam::836688625766:role/unified-deployment-mode-test`, which is trusted
only by the account's admin user. Nothing long-lived is stored.

The role is deliberately narrow, and `policy.json` is the source of truth:

- `ec2:Describe*` and `GetConsoleOutput` anywhere; everything else region-locked
  to `us-east-1`
- **destructive actions only on resources tagged
  `unified-ai.purpose=deployment-mode-test`** — it cannot delete anything it did
  not create
- `RunInstances` restricted to `t4g.nano`, `t4g.micro`, `t3.micro`, so a mistake
  cannot start something expensive
- an explicit `Deny` on every non-EC2 service

Verified rather than assumed: IAM, S3 and RDS calls are refused with an explicit
deny, an `m7g.16xlarge` is refused, and a `t4g.nano` dry-run is authorised. The
policy also blocked a legitimate action on first use — tagging security-group
*rules*, whose create action is `AuthorizeSecurityGroupEgress` rather than
`CreateSecurityGroup` — which is the right failure direction for a policy to
have.

## Teardown

Everything carries `unified-ai.purpose=deployment-mode-test` and
`unified-ai.ephemeral=true`, applied at the provider so nothing can be created
without them. `destroy` removes 19 resources and the sweep in `observe.sh`
fails if anything carrying those tags survives — which is the
`teardown-leaves-nothing-billable` assertion, not merely hygiene.
