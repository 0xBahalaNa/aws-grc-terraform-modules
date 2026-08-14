# Self-verifying evidence outputs — booleans read deployed resource attributes.

output "bucket_arn" {
  description = "ARN of the evidence bucket."
  value       = aws_s3_bucket.this.arn
}

output "bucket_id" {
  description = "Name/id of the evidence bucket."
  value       = aws_s3_bucket.this.id
}

output "bucket_regional_domain_name" {
  description = "Regional domain name of the evidence bucket."
  value       = aws_s3_bucket.this.bucket_regional_domain_name
}

# Pass-through of the key actually configured on the encryption resource,
# not var.kms_cmk_arn — criterion 9.
output "kms_cmk_arn" {
  description = "KMS CMK ARN configured on the bucket's SSE-KMS default encryption."
  value       = local.sse_default.kms_master_key_id
}

output "compliance_attestation" {
  description = "Self-verifying compliance attestation. Consumed by oscal-evidence-pipeline."
  value = {
    module            = "s3-compliant-bucket"
    module_version    = local.required_tags.module_version
    framework_targets = ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.0"]
    # concat() joins two lists. AU-9 is only claimed when the logging
    # resource exists — same length() check as access_logging_enabled.
    # https://developer.hashicorp.com/terraform/language/functions/concat
    controls_satisfied = concat(
      ["SC-28", "SC-28(1)", "SC-8", "AC-3", "AC-6", "CP-9", "SI-7", "AU-11"],
      length(aws_s3_bucket_logging.this) > 0 ? ["AU-9"] : []
    )
    environment               = var.environment
    required_compliance_scope = var.required_compliance_scope

    # Drive-slot boolean (Luigi) — algorithm + CMK ARN from the encryption
    # resource. Path uses one() because the provider types `rule` as a set.
    sse_kms_with_cmk = (
      local.sse_default.sse_algorithm == "aws:kms" &&
      can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", local.sse_default.kms_master_key_id))
    )

    bucket_key_enabled = local.sse_rule.bucket_key_enabled

    versioning_enabled = (
      aws_s3_bucket_versioning.this.versioning_configuration[0].status == "Enabled"
    )

    object_lock_governance_1yr = (
      local.object_lock_retention.mode == "GOVERNANCE" &&
      local.object_lock_retention.days >= 365
    )

    # try(jsondecode(...), false) — same idiom as iam-hardening's MFA check.
    # Bool, not BoolIfExists: aws:SecureTransport is on every request.
    tls_only_policy_attached = try(
      jsondecode(aws_s3_bucket_policy.this.policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_s3_bucket_policy.this.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false",
      false
    )

    block_public_access_all_enabled = (
      aws_s3_bucket_public_access_block.this.block_public_acls &&
      aws_s3_bucket_public_access_block.this.block_public_policy &&
      aws_s3_bucket_public_access_block.this.ignore_public_acls &&
      aws_s3_bucket_public_access_block.this.restrict_public_buckets
    )

    # length() on a count-gated resource — Lab 1 Access Analyzer idiom.
    # Must not read var.enable_access_logging.
    access_logging_enabled = length(aws_s3_bucket_logging.this) > 0

    required_tags_present = alltrue([
      for k in keys(local.required_tags) : contains(keys(aws_s3_bucket.this.tags_all), k)
    ])

    account_defaults_managed = length(aws_s3_account_public_access_block.this) > 0
  }
}
