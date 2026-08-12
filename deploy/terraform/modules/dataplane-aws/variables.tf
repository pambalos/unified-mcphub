variable "name" {
  type        = string
  description = "Prefix for created resources; distinguishes environments in one VPC."
  default     = "unified"
}

variable "vpc_id" {
  type        = string
  description = "VPC the agent workload and its sidecar live in."
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR. Used only to reach the VPC resolver for DNS."
}

variable "proxy_port" {
  type        = number
  description = "Envoy listener the agent's traffic is redirected to."
  default     = 10000
}

variable "upstream_cidrs" {
  type        = list(string)
  description = <<-EOT
    Destinations the *sidecar* may reach on 443 — the tools the agent is
    allowed to use, as a network-level backstop behind policy.

    Empty means no egress at all: the air-gapped posture, where every upstream
    is inside the perimeter and named in `internal_upstream_cidrs`. That is a
    deliberate default. A module that shipped `0.0.0.0/0` here would make the
    common case "the sidecar can reach the whole internet", which is the
    posture the product exists to replace.
  EOT
  default     = []
}

variable "internal_upstream_cidrs" {
  type        = list(string)
  description = "In-perimeter upstreams the sidecar may reach on 443."
  default     = []
}

variable "control_plane_cidrs" {
  type        = list(string)
  description = <<-EOT
    Where the control plane lives, for hybrid deployments (policy down,
    evidence up). Empty in self-hosted and air-gapped modes.

    This is the ONLY egress the engine itself is granted, and it is separate
    from `upstream_cidrs` on purpose: an operator reviewing this module should
    be able to see, in one variable, every byte that leaves for us rather than
    for a tool the agent called.
  EOT
  default     = []
}

variable "control_plane_port" {
  type        = number
  description = "HTTPS port for the control plane seam."
  default     = 443
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to every resource."
  default     = {}
}
