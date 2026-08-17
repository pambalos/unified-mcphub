# Two VPCs for the deployment-mode assertions. UAI-161.
#
# **Why two, and why the connected one is the important one.**
#
# The obvious way to test "an air-gapped deployment reaches nothing" is to build
# a VPC with no internet gateway and observe that nothing gets out. That proves
# nothing: with no route to the internet, traffic fails whether or not our
# security groups exist, and the test would pass just as happily with them
# deleted. It is a check that measures the absence of a route.
#
# So the enforcement assertions run in `connected`, where the internet is
# genuinely one hop away and the security group is the only thing in the path.
# `isolated` answers a different and also real question: does the stack function
# at all with no connectivity — does the sidecar start, enforce from a bundle it
# already has, and keep its chain.
#
# **Cost.** VPCs, subnets, gateways, route tables and security groups are free.
# The only billable things are two t4g.nano instances, up for the length of a
# run. No NAT gateway (~$0.045/hr and the one thing here that would actually
# cost money) — the probe instance sits in a public subnet instead, which is
# both cheaper and a stronger test, because egress is maximally available.
#
# **Getting results out of the isolated VPC** without internet: no SSM
# interface endpoints (~$0.01/hr each, three of them). The probe runs from
# user-data at boot and writes to the serial console, which is readable with
# `ec2:GetConsoleOutput` and costs nothing.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

provider "aws" {
  region = var.region

  # Everything this harness creates, tagged at the provider so nothing can be
  # created without it. The teardown sweep keys on these, and a resource that
  # escaped the tag would be a resource the sweep cannot see — which is the
  # failure mode "teardown leaves nothing billable" exists to catch.
  default_tags {
    tags = {
      "unified-ai.purpose"   = "deployment-mode-test"
      "unified-ai.ephemeral" = "true"
      "unified-ai.ticket"    = "UAI-161"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ami_id" {
  type        = string
  description = <<-EOT
    Resolved outside this configuration and passed in. The scoped role has no
    ssm:GetParameter — adding it to look up an AMI alias would widen the role
    for a convenience, so the bootstrap resolves it with admin credentials and
    hands it over.
  EOT
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"
}

variable "with_instances" {
  type        = bool
  default     = false
  description = <<-EOT
    Instances are opt-in so the networking can be applied, inspected and
    destroyed for nothing at all. The observation assertions need them; the
    plan-time checks do not.
  EOT
}

# ---------------------------------------------------------------------------
# connected: the internet is reachable, so a security group has to be what
# stops it
# ---------------------------------------------------------------------------

resource "aws_vpc" "connected" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "unified-test-connected" }
}

resource "aws_internet_gateway" "connected" {
  vpc_id = aws_vpc.connected.id
  tags   = { Name = "unified-test-connected" }
}

resource "aws_subnet" "agent" {
  vpc_id                  = aws_vpc.connected.id
  cidr_block              = "10.20.1.0/24"
  map_public_ip_on_launch = true
  tags                    = { Name = "unified-test-agent" }
}

resource "aws_subnet" "internal_tools" {
  vpc_id     = aws_vpc.connected.id
  cidr_block = "10.20.2.0/24"
  tags       = { Name = "unified-test-internal-tools" }
}

resource "aws_subnet" "control_plane" {
  vpc_id     = aws_vpc.connected.id
  cidr_block = "10.20.3.0/24"
  tags       = { Name = "unified-test-control-plane" }
}

resource "aws_route_table" "connected" {
  vpc_id = aws_vpc.connected.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.connected.id
  }
  tags = { Name = "unified-test-connected" }
}

resource "aws_route_table_association" "agent" {
  subnet_id      = aws_subnet.agent.id
  route_table_id = aws_route_table.connected.id
}

# The security groups under test, from the shipped self-hosted example: every
# upstream internal, no control plane, nothing outbound.
module "airgap_dataplane" {
  source = "../terraform/modules/dataplane-aws"

  name                    = "unified-airgap-test"
  vpc_id                  = aws_vpc.connected.id
  vpc_cidr                = aws_vpc.connected.cidr_block
  internal_upstream_cidrs = [aws_subnet.internal_tools.cidr_block]
  upstream_cidrs          = []
  control_plane_cidrs     = []
}

# ---------------------------------------------------------------------------
# isolated: no gateway at all
# ---------------------------------------------------------------------------

resource "aws_vpc" "isolated" {
  cidr_block           = "10.30.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "unified-test-isolated" }
}

resource "aws_subnet" "isolated" {
  vpc_id     = aws_vpc.isolated.id
  cidr_block = "10.30.1.0/24"
  tags       = { Name = "unified-test-isolated" }
}

# ---------------------------------------------------------------------------
# the probes
# ---------------------------------------------------------------------------

locals {
  # Written to the serial console because that is readable from an isolated
  # VPC. Each line is prefixed so the reader can find them in the boot noise
  # without guessing.
  probe = <<-EOT
    #!/bin/bash
    say() { echo "UAI161 $*" > /dev/console; }
    say "probe-start $(date -Is)"

    # curl with a short timeout: the interesting outcome is a *failure*, and a
    # test that waits 2 minutes for a hang is a test nobody runs twice.
    for target in https://example.com https://api.github.com; do
      if curl -s --max-time 8 -o /dev/null "$target"; then
        say "egress-REACHED $target"
      else
        say "egress-blocked $target"
      fi
    done

    # Two IMDS measurements, not one. Tokenless v1 is the credential path a
    # compromised MCP server would use; the token PUT is the path cloud-init
    # used to fetch this very script, so if it reports failed the mitigation
    # broke the boot contract and the fix is wrong, not the test.
    code=$(curl -s -o /dev/null -w '%%{http_code}' --max-time 8 http://169.254.169.254/latest/meta-data/)
    if [ "$code" = "200" ]; then
      say "imdsv1-reached"
    else
      say "imdsv1-blocked http-$code"
    fi

    token=$(curl -s --max-time 8 -X PUT http://169.254.169.254/latest/api/token \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
    if [ -n "$token" ]; then
      say "imdsv2-host-token-ok"
    else
      say "imdsv2-host-token-failed"
    fi

    say "probe-done"
  EOT
}

resource "aws_instance" "airgap_probe" {
  count = var.with_instances ? 1 : 0

  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.agent.id
  vpc_security_group_ids = [module.airgap_dataplane.agent_security_group_id]
  user_data              = local.probe

  # The 2026-08-14 run measured that security groups do not govern link-local:
  # both probes reached 169.254.169.254. This is the shipped answer, under the
  # same observation. Tokens required kills the tokenless v1 path; hop limit 1
  # means the response cannot cross a routed hop, so a containerised or
  # namespaced MCP server never sees it. `disabled` would be stronger but is
  # not honest here: cloud-init fetches user_data through this endpoint, so an
  # instance that boots by user_data cannot also claim IMDS off at launch.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = { Name = "unified-test-airgap-probe" }
}

# A control: same subnet, same internet, default security group. If this one
# also fails to reach the internet then the network is broken and the airgap
# probe's silence means nothing.
resource "aws_instance" "control" {
  count = var.with_instances ? 1 : 0

  ami           = var.ami_id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.agent.id
  user_data     = local.probe

  tags = { Name = "unified-test-control" }
}

output "connected_vpc_id" { value = aws_vpc.connected.id }
output "isolated_vpc_id" { value = aws_vpc.isolated.id }
output "airgap_probe_id" { value = try(aws_instance.airgap_probe[0].id, null) }
output "control_probe_id" { value = try(aws_instance.control[0].id, null) }
