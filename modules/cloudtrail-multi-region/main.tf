# cloudtrail-multi-region — Lab 4 module (v1.4.0)
#
# Collection: one multi-region trail to an existing Lab 2 bucket, its
# CloudWatch Logs group, and the role CloudTrail uses to write there.
# PR 2 of 3 adds alerting (metric filters, alarms, EventBridge). Athena comes
# in PR 3.
# Companion walkthrough: luigicarpio.dev/labs/2026-11-aws-lab-4-cloudtrail-audit
#
# The module does not write the bucket policy or the key policy. Both belong
# to the Lab 2 stack. It also does not create the SNS topic or write its
# policy. The README lists the statements the caller adds.

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

  metric_namespace = "GRC/Lab4"
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

# SI-4 — the CIS AWS Foundations patterns behind Security Hub CloudWatch.1,
# .3, and .4. One log group carries every region, so these see every region.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter
resource "aws_cloudwatch_log_metric_filter" "root_activity" {
  name           = "RootActivity"
  log_group_name = aws_cloudwatch_log_group.this.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootActivity"
    namespace = local.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "console_login_no_mfa" {
  name           = "ConsoleLoginNoMFA"
  log_group_name = aws_cloudwatch_log_group.this.name
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"

  metric_transformation {
    name      = "ConsoleLoginNoMFA"
    namespace = local.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "iam_policy_change" {
  name           = "IAMPolicyChange"
  log_group_name = aws_cloudwatch_log_group.this.name
  pattern        = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"

  metric_transformation {
    name      = "IAMPolicyChange"
    namespace = local.metric_namespace
    value     = "1"
  }
}

# SI-4 — one alarm per filter. metric_name and namespace are read off the
# filter, so the alarm cannot name a metric that does not exist.
# notBreaching: a filter publishes only on a match, so "missing" would leave
# the alarm gray almost always. The cost is that an alarm cannot tell no
# events from no pipeline. Pipeline health is the trail status, not the alarm.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm
resource "aws_cloudwatch_metric_alarm" "root_activity" {
  alarm_name          = "${var.name_prefix}-root-activity"
  metric_name         = aws_cloudwatch_log_metric_filter.root_activity.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.root_activity.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.critical_event_sns_topic_arn]

  tags = merge(var.tags, local.required_tags)
}

resource "aws_cloudwatch_metric_alarm" "console_login_no_mfa" {
  alarm_name          = "${var.name_prefix}-console-login-no-mfa"
  metric_name         = aws_cloudwatch_log_metric_filter.console_login_no_mfa.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.console_login_no_mfa.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.critical_event_sns_topic_arn]

  tags = merge(var.tags, local.required_tags)
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_change" {
  alarm_name          = "${var.name_prefix}-iam-policy-change"
  metric_name         = aws_cloudwatch_log_metric_filter.iam_policy_change.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.iam_policy_change.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.critical_event_sns_topic_arn]

  tags = merge(var.tags, local.required_tags)
}

# SI-4 — the seconds path, on the default bus. EventBridge is regional, so
# these rules match only events delivered in the module's region. IAM and
# root sign-in land in us-east-1. The metric-filter path sees every region
# through the one log group. That is why both paths exist.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule
resource "aws_cloudwatch_event_rule" "root_activity" {
  name  = "${var.name_prefix}-root-activity"
  state = "ENABLED"

  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail = {
      userIdentity = { type = ["Root"] }
    }
  })

  tags = merge(var.tags, local.required_tags)
}

resource "aws_cloudwatch_event_rule" "console_login_no_mfa" {
  name  = "${var.name_prefix}-console-login-no-mfa"
  state = "ENABLED"

  event_pattern = jsonencode({
    "detail-type" = ["AWS Console Sign In via CloudTrail"]
    detail = {
      eventName           = ["ConsoleLogin"]
      userIdentity        = { type = ["IAMUser"] }
      additionalEventData = { MFAUsed = ["No"] }
      responseElements    = { ConsoleLogin = ["Success"] }
    }
  })

  tags = merge(var.tags, local.required_tags)
}

resource "aws_cloudwatch_event_rule" "iam_policy_change" {
  name  = "${var.name_prefix}-iam-policy-change"
  state = "ENABLED"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion",
        "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy",
        "AttachGroupPolicy", "DetachGroupPolicy", "PutRolePolicy", "PutUserPolicy",
        "PutGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "DeleteGroupPolicy",
      ]
    }
  })

  tags = merge(var.tags, local.required_tags)
}

# The topic policy must admit events.amazonaws.com (module README). The
# provider does not add that statement the way the console does.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target
resource "aws_cloudwatch_event_target" "root_activity" {
  rule      = aws_cloudwatch_event_rule.root_activity.name
  target_id = "sns"
  arn       = var.critical_event_sns_topic_arn
}

resource "aws_cloudwatch_event_target" "console_login_no_mfa" {
  rule      = aws_cloudwatch_event_rule.console_login_no_mfa.name
  target_id = "sns"
  arn       = var.critical_event_sns_topic_arn
}

resource "aws_cloudwatch_event_target" "iam_policy_change" {
  rule      = aws_cloudwatch_event_rule.iam_policy_change.name
  target_id = "sns"
  arn       = var.critical_event_sns_topic_arn
}
