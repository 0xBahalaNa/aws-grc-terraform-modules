# Minimal Lab 4 caller — validate/plan artifact. Replace the placeholder bucket
# name and key ARN before plan. The bucket and key policies must already grant
# CloudTrail and CloudWatch Logs (module README).

module "audit_trail" {
  source = "../.."

  name_prefix               = "grc-lab4"
  log_bucket_name           = "grc-lab2-evidence-example"
  kms_key_arn               = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
  environment               = "dev"
  project_tag               = "lab-4-cloudtrail-multi-region-example"
  required_compliance_scope = "fedramp-high"
}
