# cloudtrail-multi-region — Lab 4 module (v1.4.0)
#
# PR 1 of 3, collection: one multi-region trail to an existing Lab 2 bucket,
# its CloudWatch Logs group, and the role CloudTrail uses to write there.
# Alerting (metric filters, alarms, EventBridge) and Athena come in PRs 2 and 3.
# Companion walkthrough: luigicarpio.dev/labs/2026-11-aws-lab-4-cloudtrail-audit
#
# The module does not write the bucket policy or the key policy. Both belong
# to the Lab 2 stack. The README lists the statements the caller adds.

# Partition, region, and account build the trail ARN as a string. Nothing is
# typed by hand, so the same code runs in arn:aws-us-gov.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity
data "aws_partition" "current" {}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

# required_tags is a map so merge() can overwrite by key (Lab 2.4 pattern #1 / CM-6).
# https://developer.hashicorp.com/terraform/language/functions/merge
#
# trail_arn is computed, not read off aws_cloudtrail. The role's trust policy
# needs the trail ARN, and the trail needs the role. Reading the attribute
# would be a cycle. A string built from the same name breaks it.
locals {
  required_tags = {
    compliance_scope = var.required_compliance_scope
    project          = var.project_tag
    environment      = var.environment
    managed_by       = "aws-grc-terraform-modules/cloudtrail-multi-region"
    framework_target = "FedRAMP-High,CJIS-v6.1,NIST-800-53-Rev-5"
    module_version   = "1.4.0"
  }

  trail_name     = "${var.name_prefix}-trail"
  log_group_name = "/aws/cloudtrail/${local.trail_name}"
  trail_arn      = "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
}

# AU-6 / AU-11 — the searchable copy of the trail. Retention is set here in
# one resource; the CLI build needed create-log-group then put-retention-policy.
# Encrypted with the same CMK as the S3 copy.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group
resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group_name
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, local.required_tags)
}

# The role CloudTrail assumes to write into the log group. aws:SourceArn pins
# the trust to this one trail, so no other trail can borrow it (confused deputy).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role
resource "aws_iam_role" "cloudtrail_to_cwlogs" {
  name = "CloudTrailRole-${var.name_prefix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
        }
      }
    ]
  })

  tags = merge(var.tags, local.required_tags)
}

# Two actions on this group's streams only. No logs:* and no other group.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy
resource "aws_iam_role_policy" "cloudtrail_to_cwlogs" {
  name = "cloudtrail-to-cwlogs"
  role = aws_iam_role.cloudtrail_to_cwlogs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.this.arn}:log-stream:*"
      }
    ]
  })
}

# AU-2 / AU-3 / AU-12 — the trail. AU-9 — signed hourly digests plus SSE-KMS.
# is_multi_region_trail and enable_log_file_validation are literals. There is
# no variable for either.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail
resource "aws_cloudtrail" "this" {
  name           = local.trail_name
  s3_bucket_name = var.log_bucket_name
  kms_key_id     = var.kms_key_arn

  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true

  # The CLI build needed a separate start-logging call. The provider calls
  # StartLogging itself when this is true.
  enable_logging = true

  # CloudTrail wants the group ARN with the :* stream suffix. The provider's
  # log group arn attribute does not carry it.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.this.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cwlogs.arn

  # Management events, Read and Write. No data_resource: data events are out
  # of scope for Lab 4.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = merge(var.tags, local.required_tags)

  # Lab 2.4 pattern #4. The trail references the role ARN, not the inline
  # policy, so the graph could create the trail before the policy exists.
  # CloudTrail checks at create time that the role can write to the group.
  depends_on = [aws_iam_role_policy.cloudtrail_to_cwlogs]
}
