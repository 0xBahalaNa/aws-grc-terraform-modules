# No is_multi_region_trail and no enable_log_file_validation. Both are
# literal true in main.tf. A variable that can only be one value should not
# exist, so there is nothing for a caller to turn off. Same move as Lab 2's
# missing BPA toggle and Lab 3's missing enable_flow_logs.

# Every name derives from this prefix in main.tf locals. The default rebuilds
# the Lab 4 CLI names (grc-lab4-trail, CloudTrailRole-grc-lab4), so the CLI
# build imports with a near-empty plan. 40 characters keeps the role name
# (15 + prefix) under IAM's 64.
variable "name_prefix" {
  description = "Prefix for the trail, log group, and role names. Trail = <prefix>-trail, log group = /aws/cloudtrail/<prefix>-trail, role = CloudTrailRole-<prefix>."
  type        = string
  default     = "grc-lab4"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix)) && length(var.name_prefix) <= 40
    error_message = "name_prefix must be lowercase letters, digits, and hyphens, 40 characters or fewer."
  }
}

# A name, not an ARN: aws_cloudtrail takes s3_bucket_name. Required. The
# bucket policy that lets CloudTrail write is the caller's job (module README).
variable "log_bucket_name" {
  description = "Name of the existing S3 bucket that receives trail log files and digests. Required. Expected to come from s3-compliant-bucket. The bucket policy must already grant cloudtrail.amazonaws.com; see the module README."
  type        = string
  nullable    = false
}

# Same regex as s3-compliant-bucket's kms_cmk_arn. [a-z-]* after aws is why
# arn:aws-us-gov:kms:... passes (GovCloud / CJIS). Alias ARNs fail: CloudWatch
# Logs takes a key ARN only, and one key serves both the trail and the group.
variable "kms_key_arn" {
  description = "ARN of the customer-managed KMS key that encrypts trail log files and the CloudWatch Logs group. Required. The key policy must already grant CloudTrail and CloudWatch Logs; see the module README."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", var.kms_key_arn))
    error_message = "kms_key_arn must be a customer-managed KMS key ARN (arn:aws:kms:...:key/... or arn:aws-us-gov:kms:...). No alias ARN. There is no SSE-S3 fallback."
  }
}

# Same [a-z-]* after aws as kms_key_arn, so arn:aws-us-gov:sns:... passes.
variable "critical_event_sns_topic_arn" {
  description = "SNS topic ARN the alarms and EventBridge rules publish to. Required. The topic and its policy are the caller's; see the module README."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+$", var.critical_event_sns_topic_arn))
    error_message = "critical_event_sns_topic_arn must be an SNS topic ARN (arn:aws:sns:<region>:<account>:<topic> or arn:aws-us-gov:sns:...)."
  }
}

# A name, and the caller's bucket. Separate from the log bucket. Expected to
# be SSE-KMS with the same CMK, a short expiry, and no Object Lock.
variable "athena_results_bucket_name" {
  description = "Name of the existing S3 bucket that receives Athena query results. Required. Not the log bucket; see the module README."
  type        = string
  nullable    = false
}

# CloudWatch Logs accepts a fixed list of retention values. This is that list
# from 365 up. 0 (never expire) is left out: a log group that never expires
# is a cost decision, not an AU-11 floor.
# https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutRetentionPolicy.html
variable "cloudwatch_log_retention_days" {
  description = "Retention for the CloudWatch Logs copy of the trail, in days. Default 365. Must be a CloudWatch Logs retention value of 365 or more."
  type        = number
  default     = 365
  nullable    = false

  validation {
    condition     = contains([365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.cloudwatch_log_retention_days)
    error_message = "cloudwatch_log_retention_days must be one of 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653. Under 365 fails AU-11 (1-year retention)."
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
