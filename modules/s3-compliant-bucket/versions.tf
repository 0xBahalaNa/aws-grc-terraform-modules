# Pinned to >= 1.9 for cross-variable validation (logs_destination_bucket,
# noncurrent_expiration_days). aws >= 6.22.0 is the floor that exposes
# blocked_encryption_types — not the iam-hardening 5.0 pin.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.22.0"
    }
  }
}