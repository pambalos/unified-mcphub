# BYOC / customer VPC: the plane runs in the customer's account, data never
# leaves it.
#
# The difference from air-gapped is only that the sidecar may reach named
# external SaaS tools — still an allowlist, never 0.0.0.0/0. There is no
# control plane, so evidence stays local and is exported on the customer's
# terms (SIEM, C2) rather than pushed to us.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }

variable "upstream_cidrs" {
  type        = list(string)
  description = <<-EOT
    External tool endpoints the sidecar may reach on 443, as CIDRs.

    Deliberately not a hostname list: security groups filter by address, and a
    template that accepted hostnames would have to resolve them at plan time
    and silently rot as the provider's addresses changed. For SaaS with wide or
    shifting ranges, use a VPC prefix list or an egress proxy and point this at
    that — do not reach for 0.0.0.0/0, which removes the guarantee.
  EOT
}

module "dataplane" {
  source = "../../modules/dataplane-aws"

  name           = "unified-byoc"
  vpc_id         = var.vpc_id
  vpc_cidr       = var.vpc_cidr
  upstream_cidrs = var.upstream_cidrs

  control_plane_cidrs = []

  tags = { "unified-ai.mode" = "byoc" }
}

check "upstreams_are_not_the_whole_internet" {
  assert {
    condition     = !contains(var.upstream_cidrs, "0.0.0.0/0")
    error_message = "upstream_cidrs contains 0.0.0.0/0, which defeats the egress allowlist."
  }
}

output "agent_security_group_id" { value = module.dataplane.agent_security_group_id }
output "sidecar_security_group_id" { value = module.dataplane.sidecar_security_group_id }
output "egress_summary" { value = module.dataplane.egress_summary }
