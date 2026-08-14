# s3-compliant-bucket — Lab 2 module (v1.2.1)
#
# Codifies Lab 2 console baseline: SSE-KMS with a required customer-managed
# CMK, Object Lock Governance (365-day floor), versioning forced on,
# bucket-level Block Public Access (no toggle), TLS-only bucket policy,
# optional server access logging to a consumer-supplied bucket, and one
# fixed noncurrent-version lifecycle rule.
# Companion walkthrough: luigicarpio.dev/blog/2026-07-aws-lab-2-s3-compliant-bucket

# locals is a computed-values block — not an input, not a resource. required_tags
# is a map so merge() can overwrite by key (Lab 2.4 pattern #1 / CM-6). Key set
# mirrors iam-hardening: compliance_scope, project, environment, managed_by,
# framework_target, module_version. The attestation output carries `module`
# separately, same as Lab 1.

locals {
  required_tags = {
    compliance_scope = var.required_compliance_scope
    project          = var.project_tag
    environment      = var.environment
    managed_by       = "aws-grc-terraform-modules/s3-compliant-bucket"
    framework_target = "FedRAMP-High,CJIS-v6.1,NIST-800-53-Rev-5"
    module_version   = "1.2.1"
  }

  # The AWS provider exports `rule` as a set, not a list — [0] is illegal.
  # one() unwraps a single-element set; an empty set returns null (it does
  # not error). Two or more elements error.
  # https://developer.hashicorp.com/terraform/language/functions/one
  sse_rule              = one(aws_s3_bucket_server_side_encryption_configuration.this.rule)
  sse_default           = one(local.sse_rule.apply_server_side_encryption_by_default)
  object_lock_retention = one(one(aws_s3_bucket_object_lock_configuration.this.rule).default_retention)
}

# SC-28 / AC-3 — bucket identity. object_lock_enabled must be set at create
# time; it cannot be flipped on later. Drive-slot block (Luigi).
resource "aws_s3_bucket" "this" {
  bucket              = var.bucket_name
  object_lock_enabled = true
  tags                = merge(var.tags, local.required_tags)
}

# SC-28 / SC-28(1) / SC-13 — default encryption. Sibling resource (the nested
# block on aws_s3_bucket is deprecated). Omitting kms_master_key_id would
# silently select the AWS-managed aws/s3 key — forbidden. Drive-slot block
# (Luigi); blocked_encryption_types added after review — requires AWS
# provider >= 6.22.0, matching the console's BlockedEncryptionTypes: [SSE-C].
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_cmk_arn
    }
    bucket_key_enabled       = true
    blocked_encryption_types = ["SSE-C"]
  }
}

# SI-7 / CP-9 — versioning is a separate resource, not an argument on the
# bucket. status is a literal; there is no variable that can disable it.
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = "Enabled"
  }
}

# AU-11 / AU-9 — default retention. GOVERNANCE (not COMPLIANCE) matches the
# console build; days come from the variable that validates >= 365.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object_lock_configuration
resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }
}

# AC-3 / AC-6 — all four BPA flags hardcoded. No input exists that can
# turn one off.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SC-8 — TLS-only bucket policy. jsonencode() turns an HCL object into the
# JSON string the AWS API expects (same construct as iam-hardening's MFA
# policy). Principal/Action/Resource/Condition are that object's keys.
# Bool, not BoolIfExists: aws:SecureTransport is on every request (contrast
# Lab 1's MFA key, which can be absent).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy
resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.this.arn,
        "${aws_s3_bucket.this.arn}/*",
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

# AU-9 — access logging. count is a 0-or-1 switch (not for_each — there is
# nothing to iterate). count = 0 produces an empty list; attestation reads
# length(...) > 0 and the [0] element, same idiom as iam-hardening's
# Access Analyzer. Destination is consumer-supplied — this module never
# creates a logs bucket (SSE-KMS + Object Lock are illegal on the
# destination).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging
resource "aws_s3_bucket_logging" "this" {
  count = var.enable_access_logging ? 1 : 0

  bucket        = aws_s3_bucket.this.id
  target_bucket = var.logs_destination_bucket
  target_prefix = var.logs_prefix
}

# CP-9 / AU-11 — one fixed rule, two numbers. filter {} means "all objects"
# and avoids the deprecated rule-level prefix argument. GLACIER is Flexible
# Retrieval (console name). depends_on versioning: the provider requires
# versioning to exist before a noncurrent-version rule can apply.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "evidence-retention"
    status = "Enabled"

    filter {}

    noncurrent_version_transition {
      noncurrent_days = var.noncurrent_transition_days
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_expiration_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# Account-level S3 BPA — one per account. count-gated on
# manage_account_defaults (default false) so a second module instantiation
# does not fight over it. EBS encryption-by-default was dropped: the
# resource selects the AWS-managed aws/ebs key, which this repo forbids
# (Luigi, 2026-08-13 Round 2). CMK for EBS is Lab 7.

resource "aws_s3_account_public_access_block" "this" {
  count = var.manage_account_defaults ? 1 : 0

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
