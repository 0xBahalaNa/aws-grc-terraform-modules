# Nothing here needs a Terraform newer than 1.6: no cross-variable validation.
# aws >= 6.0.0 because data.aws_region exposes region (name is retired in 6).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"
    }
  }
}
