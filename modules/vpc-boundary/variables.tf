# No enable_nat_gateway. A bool that creates or skips the NAT needs count,
# and this module always builds one zonal NAT. HA (one NAT per AZ) is a
# README note, not a resource.

variable "cidr_block" {
  description = "IPv4 CIDR for the VPC. Must be a /16. Subnet CIDRs are carved from it at the lab offsets (public .1 and .2, private .11 and .12)."
  type        = string
  default     = "10.50.0.0/16"
  nullable    = false

  # cidrsubnet() below rejects a string that is not a real network address.
  # endswith "/16" is the prefix-length floor. Shape-only on purpose: the
  # same idea as Lab 2's ARN regex.
  # https://developer.hashicorp.com/terraform/language/functions/cidrsubnet
  validation {
    condition     = can(cidrsubnet(var.cidr_block, 8, 12)) && endswith(var.cidr_block, "/16")
    error_message = "cidr_block must be an IPv4 /16 network address (example: 10.50.0.0/16)."
  }
}

variable "az_a" {
  description = "First availability zone (public-a and private-a, and the single NAT). Pass a zone name in the provider region, such as us-east-1a. Not hardcoded: GovCloud zone names differ."
  type        = string
  nullable    = false
}

# Cross-variable validation: az_b may read az_a. Terraform >= 1.9.
# This is the two-AZ floor. There is no az_count; two zones is the lab.
# https://developer.hashicorp.com/terraform/language/block/variable#cross-object-validation-conditions
variable "az_b" {
  description = "Second availability zone (public-b and private-b). Must differ from az_a."
  type        = string
  nullable    = false

  validation {
    condition     = var.az_a != var.az_b
    error_message = "az_a and az_b must name two different availability zones. One AZ fails the two-AZ floor."
  }
}

# Required. nullable = false rejects an explicit null. No default, so omitting
# it fails the plan. No enable_flow_logs toggle exists.
# [a-z-]* after aws is why arn:aws-us-gov:s3:::... passes (GovCloud / CJIS).
variable "flow_logs_bucket_arn" {
  description = "ARN of the existing S3 bucket that receives VPC Flow Logs. Required. The bucket and its CMK must grant delivery.logs.amazonaws.com; this module does not create the bucket or edit its policy. See the module README."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:s3:::", var.flow_logs_bucket_arn))
    error_message = "flow_logs_bucket_arn must be an S3 bucket ARN (arn:aws:s3:::... or arn:aws-us-gov:s3:::...). There is no flow-logs-off mode."
  }
}

variable "environment" {
  description = "Deployment environment. Used for the environment required tag."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "project_tag" {
  description = "Project identifier applied as the `project` tag on module resources."
  type        = string
}

variable "required_compliance_scope" {
  description = "Compliance baseline this module is enforcing for. Applied as the `compliance_scope` tag and passed through on the attestation output. Does not change which controls the module enforces."
  type        = string
  default     = "fedramp-high"

  validation {
    condition     = contains(["fedramp-high", "cjis-v6", "nist-800-53-rev-5"], var.required_compliance_scope)
    error_message = "required_compliance_scope must be one of: fedramp-high, cjis-v6, nist-800-53-rev-5."
  }
}

variable "tags" {
  description = "Consumer-provided tags. Merged via `merge(var.tags, local.required_tags)` so the module's compliance tags overwrite any consumer attempts to suppress them."
  type        = map(string)
  default     = {}
}
