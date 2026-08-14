terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.22.0"
    }
  }
}

# Region from AWS_REGION / AWS_DEFAULT_REGION or ~/.aws/config — not hardcoded.
provider "aws" {}
