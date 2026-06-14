# Terraform + provider version pins for iam-hardening-module.
# Pinned to >= 1.6 to use validation blocks and optional() object attributes.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}
