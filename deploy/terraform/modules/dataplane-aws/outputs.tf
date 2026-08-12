output "agent_security_group_id" {
  description = "Attach to the agent workload (ECS task, launch template, pod ENI)."
  value       = aws_security_group.agent.id
}

output "sidecar_security_group_id" {
  description = "Attach to the Envoy + unified-enforce sidecar."
  value       = aws_security_group.sidecar.id
}

output "reaches_control_plane" {
  description = <<-EOT
    Whether any egress to a control plane was provisioned. Exposed so an
    air-gapped deployment can assert it is false in a policy check rather than
    reading the plan by eye.
  EOT
  value       = length(var.control_plane_cidrs) > 0
}

output "egress_summary" {
  description = "Every destination this data plane may reach, for review and evidence."
  value = {
    agent_to         = ["sidecar:${var.proxy_port}", "dns:53"]
    sidecar_to       = concat(var.upstream_cidrs, var.internal_upstream_cidrs)
    control_plane_to = var.control_plane_cidrs
  }
}
