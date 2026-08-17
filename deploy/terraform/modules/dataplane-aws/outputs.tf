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

output "required_metadata_options" {
  description = <<-EOT
    Merge into the metadata_options of every instance or launch template that
    attaches these security groups. Security groups do not govern link-local
    traffic, so nothing this module provisions stands between a compromised
    MCP server and 169.254.169.254 — on a profiled instance, a credential
    endpoint (measured, not assumed: deploy/test-harness, 2026-08-14 run).
    Tokens-required kills tokenless IMDSv1; hop limit 1 keeps responses from
    crossing a routed hop, so containerised workloads never see them. Set
    http_endpoint = "disabled" instead wherever the workload does not boot by
    user_data and holds no role worth stealing.
  EOT
  value = {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}

output "egress_summary" {
  description = "Every destination this data plane may reach, for review and evidence."
  value = {
    agent_to         = ["sidecar:${var.proxy_port}", "dns:53"]
    sidecar_to       = concat(var.upstream_cidrs, var.internal_upstream_cidrs)
    control_plane_to = var.control_plane_cidrs
  }
}
