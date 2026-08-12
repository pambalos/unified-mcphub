# The enforcement data plane in a customer VPC — the network half of E3, as a
# reusable module. Generalises deploy/egress/aws-security-groups.tf, which is
# the same rules written flat for reading.
#
# What this provisions: the security-group topology that makes enforcement
# unavoidable. The agent workload may reach exactly one destination — the
# sidecar — plus DNS. The sidecar reaches the upstream allowlist. Optionally the
# engine reaches a control plane.
#
# What this does NOT provision: compute. Whether the agent is an ECS task, an
# EC2 instance or a pod is the customer's decision and varies more than it
# shares, so the module exposes the security groups for their launch template
# or task definition to attach. A module that also created the compute would be
# rewritten by every adopter.
#
# On a single host where agent and sidecar share a network namespace, security
# groups do not filter loopback and this module is the wrong tool — use
# deploy/egress/iptables-sidecar.sh, which is executed and tested by
# tests/integration/test_egress_no_bypass.py.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

locals {
  tags = merge(var.tags, { "unified-ai.component" = "dataplane" })
}

# --- the two identities ------------------------------------------------------

resource "aws_security_group" "agent" {
  name        = "${var.name}-agent"
  description = "Agent workloads: egress only to the unified-enforce sidecar"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-agent" })
}

resource "aws_security_group" "sidecar" {
  name        = "${var.name}-sidecar"
  description = "Envoy + unified-enforce: the only route out for agents"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-sidecar" })
}

# Both groups are declared with NO inline egress block, which is what removes
# AWS's default allow-all egress rule — the single most likely way this whole
# arrangement silently enforces nothing. Every permitted flow below is an
# explicit `aws_vpc_security_group_egress_rule`. Verify after apply:
#   aws ec2 describe-security-groups --group-ids <agent-sg> \
#     --query 'SecurityGroups[0].IpPermissionsEgress'
# An 0.0.0.0/0 entry on the agent group means there is no no-bypass guarantee.

# --- agent egress: the sidecar and DNS, nothing else -------------------------

resource "aws_vpc_security_group_egress_rule" "agent_to_sidecar" {
  security_group_id            = aws_security_group.agent.id
  referenced_security_group_id = aws_security_group.sidecar.id
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  ip_protocol                  = "tcp"
  description                  = "agent to Envoy listener (the only allowed path)"
  tags                         = local.tags
}

resource "aws_vpc_security_group_egress_rule" "agent_dns_udp" {
  security_group_id = aws_security_group.agent.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC resolver (.2 lives in the VPC CIDR)"
  tags              = local.tags
}

resource "aws_vpc_security_group_egress_rule" "agent_dns_tcp" {
  security_group_id = aws_security_group.agent.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  description       = "DNS over TCP: large responses fall back to it, and a lock that breaks resolution gets removed"
  tags              = local.tags
}

# --- sidecar ingress: only from agents ---------------------------------------

resource "aws_vpc_security_group_ingress_rule" "sidecar_from_agent" {
  security_group_id            = aws_security_group.sidecar.id
  referenced_security_group_id = aws_security_group.agent.id
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  ip_protocol                  = "tcp"
  description                  = "Envoy listener, reachable only by the agent group"
  tags                         = local.tags
}

# --- sidecar egress: the upstream allowlist ----------------------------------
# Defence in depth *behind* policy, not instead of it: policy decides which tool
# a principal may call, this decides which hosts the box can reach at all.

resource "aws_vpc_security_group_egress_rule" "sidecar_upstreams" {
  for_each          = toset(var.upstream_cidrs)
  security_group_id = aws_security_group.sidecar.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "External upstream (allowlisted)"
  tags              = local.tags
}

resource "aws_vpc_security_group_egress_rule" "sidecar_internal_upstreams" {
  for_each          = toset(var.internal_upstream_cidrs)
  security_group_id = aws_security_group.sidecar.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "In-perimeter upstream"
  tags              = local.tags
}

resource "aws_vpc_security_group_egress_rule" "sidecar_dns_udp" {
  security_group_id = aws_security_group.sidecar.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "The sidecar resolves upstream names"
  tags              = local.tags
}

# --- the control-plane seam (hybrid only) ------------------------------------
# Policies down, evidence up. Kept as its own rule set so an operator can see
# every byte that leaves for *us* rather than for a tool the agent called, and
# so air-gapped deployments can confirm the list is empty.

resource "aws_vpc_security_group_egress_rule" "sidecar_control_plane" {
  for_each          = toset(var.control_plane_cidrs)
  security_group_id = aws_security_group.sidecar.id
  cidr_ipv4         = each.value
  from_port         = var.control_plane_port
  to_port           = var.control_plane_port
  ip_protocol       = "tcp"
  description       = "Control plane: policy pull and evidence push"
  tags              = local.tags
}
