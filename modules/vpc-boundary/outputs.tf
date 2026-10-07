# Self-verifying evidence outputs — booleans read deployed resource attributes.

output "vpc_id" {
  description = "ID of the enclave VPC."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs in order: az_a, then az_b."
  value       = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

output "private_subnet_ids" {
  description = "Private subnet IDs in order: az_a, then az_b."
  value       = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

output "security_group_ids" {
  description = "Security group IDs keyed edge (public-alb-443), app (app-from-alb), data (data-from-app), vpce (vpce-443)."
  value = {
    edge = aws_security_group.edge.id
    app  = aws_security_group.app.id
    data = aws_security_group.data.id
    vpce = aws_security_group.vpce.id
  }
}

output "private_route_table_id" {
  description = "ID of rt-private. Its default route is the NAT; it has no IGW route."
  value       = aws_route_table.private.id
}

output "flow_log_id" {
  description = "ID of the VPC flow log."
  value       = aws_flow_log.this.id
}

output "compliance_attestation" {
  description = "Self-verifying compliance attestation. Booleans are read from resource attributes, not from variables."
  value = {
    module            = "vpc-boundary"
    module_version    = local.required_tags.module_version
    framework_targets = ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.1"]
    # The list is the mapping. The booleans below are the checks.
    # AU-9 is not in the list: object encryption and Object Lock live on the
    # destination bucket (s3-compliant-bucket), not on the flow log resource.
    controls_satisfied = [
      "SC-7",
      "SC-7(3)",
      "SC-7(5)",
      "AC-4",
      "AU-2",
      "AU-3",
      "AU-12",
    ]
    environment               = var.environment
    required_compliance_scope = var.required_compliance_scope

    # The private 0.0.0.0/0 route resource. gateway_id is unset when the
    # route's target is the NAT. This does not scan routes added outside
    # the module. The S3 endpoint's prefix-list route is not an IGW route.
    private_has_no_igw_route = (
      aws_route.private_default.destination_cidr_block == "0.0.0.0/0" &&
      aws_route.private_default.nat_gateway_id == aws_nat_gateway.this.id &&
      (aws_route.private_default.gateway_id == null || aws_route.private_default.gateway_id == "")
    )

    flow_logs_all_traffic = aws_flow_log.this.traffic_type == "ALL"

    # Same ARN shape as the variable validation, read off the flow log
    # resource rather than off var.flow_logs_bucket_arn.
    flow_logs_to_s3 = (
      aws_flow_log.this.log_destination_type == "s3" &&
      can(regex("^arn:aws[a-z-]*:s3:::", aws_flow_log.this.log_destination))
    )

    s3_gateway_endpoint_present = (
      aws_vpc_endpoint.s3.vpc_endpoint_type == "Gateway" &&
      contains(aws_vpc_endpoint.s3.route_table_ids, aws_route_table.private.id)
    )

    kms_interface_endpoint_present = (
      aws_vpc_endpoint.kms.vpc_endpoint_type == "Interface" &&
      aws_vpc_endpoint.kms.private_dns_enabled
    )

    # for builds a list of bools, one per required tag key. alltrue ANDs them.
    # This is not for_each: nothing is created per key.
    # https://developer.hashicorp.com/terraform/language/expressions/for
    required_tags_present = alltrue([
      for k in keys(local.required_tags) : contains(keys(aws_vpc.this.tags_all), k)
    ])
  }
}
