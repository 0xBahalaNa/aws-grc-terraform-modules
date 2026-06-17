# Terraform + provider version pins for iam-hardening-module.
# Pinned to >= 1.9 for cross-variable validation blocks (var.environment in enable_access_analyzer).
# optional() object attributes require >= 1.3; validation blocks require >= 0.13.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}
