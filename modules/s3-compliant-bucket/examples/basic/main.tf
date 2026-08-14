# Minimal Lab 2 caller — validate/plan artifact. Replace the placeholder CMK ARN before apply.
module "evidence_bucket" {
  source = "../.."

  bucket_name               = "grc-lab2-evidence-example"
  kms_cmk_arn               = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000" # placeholder — replace
  environment               = "dev"
  project_tag               = "lab-2-s3-compliant-bucket-example"
  required_compliance_scope = "fedramp-high"
  enable_access_logging     = true
  logs_destination_bucket   = "grc-lab2-access-logs-example"
}
