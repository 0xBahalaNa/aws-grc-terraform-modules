# iam-hardening — Lab 1 module
#
# Status: v0.1.0 SCAFFOLD. The variable contracts, required-tag merging, and
# compliance_attestation output structure are in place. Resource implementations
# (admin role with MFA-required trust policy, permissions boundary, separated
# service role, account password policy, CJI-user tagging) land per the Lab 1
# implementation PR (~2026-06-30). The companion Console walkthrough lives on
# luigicarpio.dev/blog.

# Required compliance tags layered on top of consumer-provided tags.
# Argument order is deliberate — required tags overwrite consumer attempts to
# suppress them. This is the CM-3 enforcement primitive every module reuses.
locals {
  required_tags = {
    compliance_scope = var.required_compliance_scope
    managed_by       = "aws-grc-terraform-modules/iam-hardening"
    framework_target = "FedRAMP-High,CJIS-v6.0,NIST-800-53-Rev-5"
    module_version   = "0.1.0"
  }

  merged_tags = merge(var.tags, local.required_tags)
}

# Implementation TODO (Lab 1 PR):
#
#   resource "aws_iam_role" "admin" {
#     # IA-2(1)(2) — assume_role_policy requires aws:MultiFactorAuthPresent
#     # AC-6        — permissions_boundary attached
#     # AC-2 delta  — cji_user_role tag when var.cji_users_enabled is true
#     tags = local.merged_tags
#   }
#
#   resource "aws_iam_policy" "admin_boundary" { ... }       # AC-6 permissions boundary
#   resource "aws_iam_role"   "service"        { ... }       # AC-5 separation of duties
#   resource "aws_iam_account_password_policy" "this" { ... } # IA-5 authenticator mgmt
#
# Each resource's attributes feed the compliance_attestation output's per-control
# booleans (e.g., the admin role's assume_role_policy is parsed to verify the
# aws:MultiFactorAuthPresent condition is actually present in deployed state).
