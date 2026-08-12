# Self-hosted / air-gapped: nothing leaves the perimeter.
#
# The strictest mode and the one C3 calls "fully air-gapped". Every upstream is
# internal, there is no control plane, and telemetry stays in-perimeter
# (otel.enabled is off by default; Tempo or Langfuse, if used, are internal).
#
# The property worth asserting here is a negative one: `reaches_control_plane`
# must be false. A deployment that quietly grew an outbound rule to us would
# still "work", which is exactly why it needs to fail a check rather than a
# review.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }

variable "internal_upstream_cidrs" {
  type        = list(string)
  description = "In-perimeter tools the agent is allowed to reach."
}

module "dataplane" {
  source = "../../modules/dataplane-aws"

  name                    = "unified-airgap"
  vpc_id                  = var.vpc_id
  vpc_cidr                = var.vpc_cidr
  internal_upstream_cidrs = var.internal_upstream_cidrs

  # Both empty, deliberately: no internet upstreams, no control plane.
  upstream_cidrs      = []
  control_plane_cidrs = []

  tags = { "unified-ai.mode" = "self-hosted" }
}

check "no_egress_to_us" {
  assert {
    condition     = module.dataplane.reaches_control_plane == false
    error_message = "Air-gapped mode provisioned egress to a control plane."
  }
}

output "agent_security_group_id" { value = module.dataplane.agent_security_group_id }
output "sidecar_security_group_id" { value = module.dataplane.sidecar_security_group_id }
