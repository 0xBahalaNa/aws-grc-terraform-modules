# Drive-slot variable (Luigi). Required + nullable = false + key-ARN regex
# (resource type key/, not alias/). [a-z-]* after aws is why
# arn:aws-us-gov:kms:...:key/... passes (GovCloud / CJIS). Alias ARNs
# including alias/aws/s3 fail. Residual: an AWS-managed *key* ARN still
# shape-passes — document in the M2 README (no live key_manager lookup).
variable "kms_cmk_arn" {
  description = "ARN of the customer-managed KMS CMK used for SSE-KMS. Must be a key ARN (not an alias). Required; null, aliases, and non-KMS ARNs fail at plan time. No SSE-S3 fallback exists."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", var.kms_cmk_arn))
    error_message = "kms_cmk_arn must be a customer-managed KMS key ARN (arn:aws:kms:... or arn:aws-us-gov:kms:...). SSE-S3 and AWS-managed keys are not permitted. No alias ARN."
  }
}

variable "bucket_name" {
  description = "S3 bucket name. Must satisfy AWS naming (3–63 chars, lowercase letters, digits, hyphens)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be 3–63 characters, start and end with a lowercase letter or digit, and contain only lowercase letters, digits, and hyphens."
  }
}

# AU-11 / CJIS AU-11 (P4) — 1-year floor. Default is the floor; lower values fail
# at plan time. HCL validation has no if: this is a straight comparison.
variable "object_lock_retention_days" {
  description = "Object Lock default retention in days (GOVERNANCE). Fail-closed at the CJIS / AU-11 1-year floor."
  type        = number
  default     = 365

  validation {
    condition     = var.object_lock_retention_days >= 365
    error_message = "object_lock_retention_days must be >= 365 (CJIS / AU-11 1-year retention floor)."
  }
}

variable "enable_access_logging" {
  description = "Attach S3 server access logging. Destination bucket is consumer-supplied (this module never creates a logs bucket). Cannot be disabled in prod."
  type        = bool
  default     = true

  # Same (A → B) ≡ (¬A ∨ B) shape as iam-hardening's enable_access_analyzer.
  validation {
    condition     = var.environment != "prod" || var.enable_access_logging
    error_message = "enable_access_logging cannot be disabled in prod (AU-9 / CM-6 baseline config)."
  }
}

# Lab 2.4 pattern #2: (A → B) ≡ (¬A ∨ B). If logging is on, a destination
# must be set. Cross-variable validation requires terraform >= 1.9.
# https://developer.hashicorp.com/terraform/language/block/variable#cross-object-validation-conditions
variable "logs_destination_bucket" {
  description = "Name of the consumer-supplied access-logs bucket. Required when enable_access_logging is true. Must not use SSE-KMS or Object Lock — S3 log delivery forbids both."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_access_logging || (var.logs_destination_bucket != null && var.logs_destination_bucket != "")
    error_message = "logs_destination_bucket must be set when enable_access_logging is true. This module does not create a logs bucket."
  }

  # Self-logging is statically invalid: this bucket has SSE-KMS + Object Lock,
  # both forbidden on an S3 log destination. null != name is true, so this
  # stays silent when logging is off and the destination is unset.
  validation {
    condition     = var.logs_destination_bucket != var.bucket_name
    error_message = "logs_destination_bucket cannot be the same as bucket_name (S3 log delivery forbids SSE-KMS and Object Lock on the destination)."
  }
}

variable "logs_prefix" {
  description = "Key prefix written into the destination logs bucket."
  type        = string
  default     = "access-logs/"
}

variable "noncurrent_transition_days" {
  description = "Days a noncurrent version waits before transitioning to GLACIER (Flexible Retrieval)."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_transition_days >= 1
    error_message = "noncurrent_transition_days must be >= 1."
  }
}

# Lifecycle may not undercut Object Lock (console beat: 730 > 365).
# Cross-variable: expiration days >= retention days.
variable "noncurrent_expiration_days" {
  description = "Days a noncurrent version waits before expiration. Must be >= object_lock_retention_days so lifecycle cannot undercut Object Lock."
  type        = number
  default     = 730

  validation {
    condition     = var.noncurrent_expiration_days >= var.object_lock_retention_days
    error_message = "noncurrent_expiration_days must be >= object_lock_retention_days (lifecycle must not undercut the Object Lock floor)."
  }

  validation {
    condition     = var.noncurrent_expiration_days > var.noncurrent_transition_days
    error_message = "noncurrent_expiration_days must be > noncurrent_transition_days (S3 rejects a lifecycle rule that expires before it transitions)."
  }
}

variable "manage_account_defaults" {
  description = "Create the account-level S3 Block Public Access singleton. Default false so a second instantiation does not collide. Set true on exactly one module call per account. Does not manage EBS encryption-by-default (that resource uses the AWS-managed aws/ebs key; CMK is Lab 7)."
  type        = bool
  default     = false
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
