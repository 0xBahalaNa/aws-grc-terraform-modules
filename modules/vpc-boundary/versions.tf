# Pinned to >= 1.9 for the az_a != az_b cross-variable validation.
# aws >= 6.24.0 is the floor that exposes availability_mode on aws_nat_gateway
# (zonal vs regional). The console offered regional; this module sets zonal.
# https://developer.hashicorp.com/terraform/language/block/variable#cross-object-validation-conditions

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.24.0"
    }
  }
}
