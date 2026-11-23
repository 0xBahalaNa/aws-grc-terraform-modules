# Self-verifying evidence outputs — booleans read deployed resource attributes.

output "trail_arn" {
  description = "ARN of the multi-region trail."
  value       = aws_cloudtrail.this.arn
}

output "trail_name" {
  description = "Name of the trail. The bucket and key policies' aws:SourceArn must name this trail."
  value       = aws_cloudtrail.this.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch Logs group that receives the trail (no :* suffix)."
  value       = aws_cloudwatch_log_group.this.arn
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch Logs group. Metric filters and Logs Insights queries target this name."
  value       = aws_cloudwatch_log_group.this.name
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup that holds the saved review queries."
  value       = aws_athena_workgroup.audit.name
}

output "athena_database_name" {
  description = "Name of the Glue database the cloudtrail_logs table lives in."
  value       = aws_glue_catalog_database.audit.name
}

output "compliance_attestation" {
  description = "Self-verifying compliance attestation. Booleans are read from resource attributes, not from variables."
  value = {
    module            = "cloudtrail-multi-region"
    module_version    = local.required_tags.module_version
    framework_targets = ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.1"]
    # The list is the mapping. The booleans below are the checks.
    controls_satisfied = [
      "AU-2",
      "AU-3",
      "AU-6",
      "AU-7",
      "AU-9",
      "AU-11",
      "AU-12",
      "SI-4",
    ]
    # G-5: the gap is in the output, not only the README. Logs sit in the
    # account they describe; a separate log-archive account would meet it.
    known_gaps = ["AU-9(2)"]

    environment               = var.environment
    required_compliance_scope = var.required_compliance_scope

    # The provider refreshes enable_logging from the live trail status, so a
    # stop-logging run outside Terraform flips this after the next refresh.
    logging_enabled     = aws_cloudtrail.this.enable_logging
    multi_region        = aws_cloudtrail.this.is_multi_region_trail
    log_file_validation = aws_cloudtrail.this.enable_log_file_validation

    # Same key-ARN shape as the variable validation, read off both resources
    # rather than off var.kms_key_arn.
    kms_encrypted = (
      can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", aws_cloudtrail.this.kms_key_id)) &&
      can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", aws_cloudwatch_log_group.this.kms_key_id))
    )

    cloudwatch_retention_365 = aws_cloudwatch_log_group.this.retention_in_days >= 365

    # Equality, not just non-empty: the trail points at this module's group
    # and role. A null attribute compares false instead of erroring.
    cloudwatch_delivery_configured = (
      aws_cloudtrail.this.cloud_watch_logs_group_arn == "${aws_cloudwatch_log_group.this.arn}:*" &&
      aws_cloudtrail.this.cloud_watch_logs_role_arn == aws_iam_role.cloudtrail_to_cwlogs.arn
    )

    management_events_all = (
      aws_cloudtrail.this.event_selector[0].read_write_type == "All" &&
      aws_cloudtrail.this.event_selector[0].include_management_events
    )

    # for builds a list of bools, one per required tag key. alltrue ANDs them.
    # This is not for_each: nothing is created per key.
    # https://developer.hashicorp.com/terraform/language/expressions/for
    required_tags_present = alltrue([
      for k in keys(local.required_tags) : contains(keys(aws_cloudtrail.this.tags_all), k)
    ])

    # AU-6: the review path is configured and encrypted. It does not prove
    # anyone ran a review. That is operating evidence (weekly under CJIS).
    athena_review_configured = (
      aws_athena_workgroup.audit.configuration[0].enforce_workgroup_configuration &&
      aws_athena_workgroup.audit.configuration[0].result_configuration[0].encryption_configuration[0].encryption_option == "SSE_KMS" &&
      can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", aws_athena_workgroup.audit.configuration[0].result_configuration[0].encryption_configuration[0].kms_key_arn)) &&
      aws_athena_workgroup.audit.configuration[0].result_configuration[0].output_location == "s3://${var.athena_results_bucket_name}/"
    )

    # SI-4: the alarms and rules exist, are on, and point at the topic. It does
    # not prove the topic delivers. The step 13 alert test does that.
    critical_alarms_present = (
      alltrue([
        for a in [
          aws_cloudwatch_metric_alarm.root_activity,
          aws_cloudwatch_metric_alarm.console_login_no_mfa,
          aws_cloudwatch_metric_alarm.iam_policy_change,
        ] : a.actions_enabled && contains(a.alarm_actions, var.critical_event_sns_topic_arn)
      ]) &&
      alltrue([
        for r in [
          aws_cloudwatch_event_rule.root_activity,
          aws_cloudwatch_event_rule.console_login_no_mfa,
          aws_cloudwatch_event_rule.iam_policy_change,
        ] : r.state == "ENABLED"
      ]) &&
      alltrue([
        for t in [
          aws_cloudwatch_event_target.root_activity,
          aws_cloudwatch_event_target.console_login_no_mfa,
          aws_cloudwatch_event_target.iam_policy_change,
        ] : t.arn == var.critical_event_sns_topic_arn
      ])
    )
  }
}
