# cloudtrail-multi-region — Lab 4 module (v1.4.0)
#
# Collection: one multi-region trail to an existing Lab 2 bucket, its
# CloudWatch Logs group, and the role CloudTrail uses to write there.
# Alerting: metric filters, alarms, and EventBridge rules to an SNS topic.
# Review: an Athena workgroup, a Glue database, and saved queries.
# Companion walkthrough: luigicarpio.dev/labs/2026-11-aws-lab-4-cloudtrail-audit
#
# The module does not write the bucket policy or the key policy. Both belong
# to the Lab 2 stack. It also does not create the SNS topic or write its
# policy, or the Athena results bucket. The README lists the statements the
# caller adds.

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

# AU-6 / AU-9 — the workgroup reviewers run queries in. Enforced config means
# a user cannot redirect results to an unencrypted location. Results carry log
# content, so they use the CMK. The results bucket is not the WORM log bucket:
# results are derived and reproducible, and Object Lock would hold every
# result file for a year.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup
resource "aws_athena_workgroup" "audit" {
  name  = "audit-queries"
  state = "ENABLED"

  configuration {
    enforce_workgroup_configuration = true

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }

    result_configuration {
      output_location = "s3://${var.athena_results_bucket_name}/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = var.kms_key_arn
      }
    }
  }

  tags = merge(var.tags, local.required_tags)
}

# Glue, not aws_athena_database. The Athena resource runs a CREATE DATABASE
# query; the Glue resource writes the catalog entry directly.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_catalog_database
resource "aws_glue_catalog_database" "audit" {
  name = "cloudtrail_audit"

  tags = merge(var.tags, local.required_tags)
}

# The enabled regions at plan time become the region partition values.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/regions
data "aws_regions" "enabled" {}

# The table is created by running this query once, so it sits outside
# Terraform state (README scope limits). aws_glue_catalog_table would put it
# in state at about 80 lines of schema.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_named_query
resource "aws_athena_named_query" "create_table" {
  name        = "create-cloudtrail-logs-table"
  description = "Run once. Creates the partition-projected cloudtrail_logs table."
  workgroup   = aws_athena_workgroup.audit.name
  database    = aws_glue_catalog_database.audit.name

  # The date partition is day, not AWS's timestamp: timestamp is reserved.
  # Projection computes S3 prefixes from the WHERE clause, so a day filter
  # bounds the scan. NOW-1YEARS matches the AU-11 one-year floor. The column
  # list is trimmed; JsonSerDe ignores keys the table does not declare.
  # $${region} and $${day} escape HCL so Athena receives ${region} and ${day}.
  query = <<-EOT
    CREATE EXTERNAL TABLE cloudtrail_logs (
      eventversion STRING,
      useridentity STRUCT<
        type: STRING, principalid: STRING, arn: STRING, accountid: STRING, invokedby: STRING, accesskeyid: STRING, username: STRING,
        sessioncontext: STRUCT<
          attributes: STRUCT<mfaauthenticated: STRING, creationdate: STRING>,
          sessionissuer: STRUCT<type: STRING, principalid: STRING, arn: STRING, accountid: STRING, username: STRING>
        >
      >,
      eventtime STRING, eventsource STRING, eventname STRING, awsregion STRING, sourceipaddress STRING, useragent STRING,
      errorcode STRING, errormessage STRING, requestparameters STRING, responseelements STRING, additionaleventdata STRING,
      requestid STRING, eventid STRING, readonly STRING, eventtype STRING, recipientaccountid STRING
    )
    PARTITIONED BY (region STRING, day STRING)
    ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION 's3://${var.log_bucket_name}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/'
    TBLPROPERTIES (
      'projection.enabled' = 'true',
      'projection.region.type' = 'enum',
      'projection.region.values' = '${join(",", sort(data.aws_regions.enabled.names))}',
      'projection.day.type' = 'date',
      'projection.day.format' = 'yyyy/MM/dd',
      'projection.day.range' = 'NOW-1YEARS,NOW',
      'projection.day.interval' = '1',
      'projection.day.interval.unit' = 'DAYS',
      'storage.location.template' = 's3://${var.log_bucket_name}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/$${region}/$${day}'
    )
  EOT
}

resource "aws_athena_named_query" "au6_root_activity" {
  name        = "au6-root-activity-90d"
  description = "AU-6: every root call in the last 90 days, newest first."
  workgroup   = aws_athena_workgroup.audit.name
  database    = aws_glue_catalog_database.audit.name

  query = <<-EOT
    SELECT eventtime, eventsource, eventname, awsregion, sourceipaddress, errorcode
    FROM cloudtrail_logs
    WHERE useridentity.type = 'Root'
      AND day >= date_format(current_timestamp - interval '90' day, '%Y/%m/%d')
    ORDER BY eventtime DESC;
  EOT
}

# No region filter. IAM events land in us-east-1, or us-gov-west-1 in GovCloud,
# and eventsource alone finds them in either partition. The day filter bounds
# the scan.
resource "aws_athena_named_query" "ac2_iam_changes_by_actor" {
  name        = "ac2-iam-changes-by-actor"
  description = "AC-2: IAM write calls in the last 90 days, counted by actor and event."
  workgroup   = aws_athena_workgroup.audit.name
  database    = aws_glue_catalog_database.audit.name

  query = <<-EOT
    SELECT useridentity.arn AS actor, eventname, count(*) AS calls
    FROM cloudtrail_logs
    WHERE eventsource = 'iam.amazonaws.com'
      AND readonly = 'false'
      AND day >= date_format(current_timestamp - interval '90' day, '%Y/%m/%d')
    GROUP BY useridentity.arn, eventname
    ORDER BY calls DESC;
  EOT
}

resource "aws_athena_named_query" "si4_calls_per_region" {
  name        = "si4-calls-per-region-per-day"
  description = "SI-4: API calls per region per day over the last 30 days, busiest first."
  workgroup   = aws_athena_workgroup.audit.name
  database    = aws_glue_catalog_database.audit.name

  query = <<-EOT
    SELECT region, day, count(*) AS calls
    FROM cloudtrail_logs
    WHERE day >= date_format(current_timestamp - interval '30' day, '%Y/%m/%d')
    GROUP BY region, day
    ORDER BY calls DESC
    LIMIT 50;
  EOT
}
