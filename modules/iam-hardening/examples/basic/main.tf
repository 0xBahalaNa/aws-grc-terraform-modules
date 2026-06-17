# Minimal Lab 1 caller — dev/staging only. Plan before apply; never apply from a laptop with local state in prod.
module "iam_baseline" {
  source = "../.."

  environment               = "dev"
  project_tag               = "lab-1-iam-hardening-example"
  required_compliance_scope = "fedramp-high"
  cji_users_enabled         = true
}
