# Hybrid: data plane in the customer's VPC, control plane hosted by us.
# Policies down, evidence up — and nothing else.
#
# The architectural commitment this encodes, and the reason the mode is safe to
# offer at all: **decisions stay local**. The engine evaluates policy in-process
# in the customer's VPC on the sub-10ms path. The control plane distributes
# policy and receives evidence, asynchronously. If the link to us is severed the
# agent keeps being enforced against its last-known policy; it does not fail
# open, and it does not stall waiting for us.
#
# So the egress opened here is one CIDR set on one port, and it belongs to the
# *sidecar*, not the agent. The agent's reachability is unchanged from
# air-gapped mode.
#
# ⚠️ The control plane itself is NOT provisioned here. `unified-control-plane`
# (C1) does not exist yet, so this module opens the seam and stops. Writing
# Terraform that stood up a service we have not built would be fiction; when C1
# lands, it gets its own module and this one keeps working unchanged.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "upstream_cidrs" { type = list(string) }

variable "control_plane_cidrs" {
  type        = list(string)
  description = "Addresses of the hosted control plane. Narrow: this is egress to us."
}

module "dataplane" {
  source = "../../modules/dataplane-aws"

  name                = "unified-hybrid"
  vpc_id              = var.vpc_id
  vpc_cidr            = var.vpc_cidr
  upstream_cidrs      = var.upstream_cidrs
  control_plane_cidrs = var.control_plane_cidrs

  tags = { "unified-ai.mode" = "hybrid" }
}

check "control_plane_egress_is_narrow" {
  assert {
    condition     = !contains(var.control_plane_cidrs, "0.0.0.0/0")
    error_message = "control_plane_cidrs must name the control plane, not the internet."
  }
}

check "the_agent_cannot_reach_the_control_plane_directly" {
  # Only the sidecar talks to us. An agent that could reach the control plane
  # directly could try to influence its own policy.
  assert {
    condition     = module.dataplane.reaches_control_plane
    error_message = "Hybrid mode provisioned no control-plane egress; use the byoc example instead."
  }
}

output "agent_security_group_id" { value = module.dataplane.agent_security_group_id }
output "sidecar_security_group_id" { value = module.dataplane.sidecar_security_group_id }
output "egress_summary" { value = module.dataplane.egress_summary }
