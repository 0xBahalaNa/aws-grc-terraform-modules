# Minimal Lab 4 caller — validate/plan artifact. Replace the placeholder bucket
# names, key ARN, and topic ARN before plan. The Athena results bucket is a
# second bucket, not the log bucket. The bucket and key policies must
# already grant CloudTrail and CloudWatch Logs, and the topic policy must admit
# events.amazonaws.com (module README).

module "audit_trail" {
  source = "../.."

  name_prefix                  = "grc-lab4"
  log_bucket_name              = "grc-lab2-evidence-example"
  kms_key_arn                  = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
  critical_event_sns_topic_arn = "arn:aws:sns:us-east-1:111122223333:grc-lab4-critical-events"
  athena_results_bucket_name   = "grc-lab4-athena-results-example"
  environment                  = "dev"
  project_tag                  = "lab-4-cloudtrail-multi-region-example"
  required_compliance_scope    = "fedramp-high"
}
