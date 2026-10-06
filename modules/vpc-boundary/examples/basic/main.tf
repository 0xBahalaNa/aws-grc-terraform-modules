# Minimal Lab 3 caller — validate/plan artifact. Replace the placeholder bucket
# ARN before plan. Plan creates a NAT gateway, which bills hourly; destroy it
# in the same sitting.

module "enclave" {
  source = "../.."

  cidr_block                = "10.50.0.0/16"
  az_a                      = "us-east-1a"
  az_b                      = "us-east-1b"
  flow_logs_bucket_arn      = "arn:aws:s3:::grc-lab2-evidence-example"
  environment               = "dev"
  project_tag               = "lab-3-vpc-boundary-example"
  required_compliance_scope = "fedramp-high"
}
