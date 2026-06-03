# Terraform + provider version pins for iam-hardening module.
# Pinned to >= 1.6 to use the typed `validation` block and `optional()` object
# attributes the cross-variable compliance contracts depend on.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}
