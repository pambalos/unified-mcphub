# AWS egress lock — agent instances/tasks may only reach the proxy. E3.
#
# Security groups are stateful and destination-scoped, so the guarantee is:
# the agent SG has NO egress rule except to the proxy SG (plus DNS to the VPC
# resolver). Anything else the agent tries is dropped at the ENI.
#
# On EC2 the proxy may be a sidecar process on the same host — in that case use
# deploy/egress/iptables-sidecar.sh instead; SGs do not filter loopback.
# This file is for the split topology: agent tasks -> proxy fleet/NLB.

variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }

resource "aws_security_group" "agent" {
  name        = "unified-agent"
  description = "Agent workloads: egress only to the unified-enforce proxy"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "proxy" {
  name        = "unified-proxy"
  description = "Envoy + unified-enforce: the only route out for agents"
  vpc_id      = var.vpc_id
}

# --- agent egress: proxy + DNS, nothing else ----------------------------------

resource "aws_vpc_security_group_egress_rule" "agent_to_proxy" {
  security_group_id            = aws_security_group.agent.id
  referenced_security_group_id = aws_security_group.proxy.id
  from_port                    = 10000
  to_port                      = 10000
  ip_protocol                  = "tcp"
  description                  = "agent to Envoy listener (the only allowed path)"
}

resource "aws_vpc_security_group_egress_rule" "agent_dns_udp" {
  security_group_id = aws_security_group.agent.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC resolver (.2 address lives in the VPC CIDR)"
}

# NOTE: deliberately no 0.0.0.0/0 egress rule on the agent SG. AWS adds a
# permissive default egress rule to new security groups — Terraform's
# aws_security_group resource removes it when managed with explicit
# aws_vpc_security_group_egress_rule resources, but verify with:
#   aws ec2 describe-security-groups --group-ids <agent-sg> --query \
#     'SecurityGroups[0].IpPermissionsEgress'
# An 0.0.0.0/0 entry here means there is no no-bypass guarantee.

# --- ingress on the proxy: only from agents -----------------------------------

resource "aws_vpc_security_group_ingress_rule" "proxy_from_agent" {
  security_group_id            = aws_security_group.proxy.id
  referenced_security_group_id = aws_security_group.agent.id
  from_port                    = 10000
  to_port                      = 10000
  ip_protocol                  = "tcp"
}

# --- proxy egress: the upstream allowlist (defense in depth behind policy) ----

resource "aws_vpc_security_group_egress_rule" "proxy_https" {
  security_group_id = aws_security_group.proxy.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Upstreams. Tighten to specific CIDRs/prefix lists in regulated or air-gapped modes."
}
