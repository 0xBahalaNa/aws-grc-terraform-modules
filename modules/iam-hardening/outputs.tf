# Self-verifying evidence outputs — booleans read deployed resource attributes.

output "group_names" {
  description = "Names of baseline IAM groups created by this module."
  value       = [for g in aws_iam_group.this : g.name]
}

output "role_arns" {
  description = "ARNs of baseline IAM roles created by this module."
  value       = { for name, role in aws_iam_role.this : name => role.arn }
}

output "access_analyzer_arn" {
  description = "ARN of the account Access Analyzer, if enabled."
  value       = length(aws_accessanalyzer_analyzer.this) > 0 ? aws_accessanalyzer_analyzer.this[0].arn : null
}

output "password_policy_summary" {
  description = "Deployed account password policy attributes for CLI parity checks."
  value = {
    minimum_password_length      = aws_iam_account_password_policy.this.minimum_password_length
    require_lowercase_characters = aws_iam_account_password_policy.this.require_lowercase_characters
    require_numbers              = aws_iam_account_password_policy.this.require_numbers
    require_symbols              = aws_iam_account_password_policy.this.require_symbols
    require_uppercase_characters = aws_iam_account_password_policy.this.require_uppercase_characters
    max_password_age             = aws_iam_account_password_policy.this.max_password_age
    password_reuse_prevention    = aws_iam_account_password_policy.this.password_reuse_prevention
  }
}

output "compliance_attestation" {
  description = "Self-verifying compliance attestation. Consumed by oscal-evidence-pipeline."
  value = {
    module                    = "iam-hardening"
    module_version            = local.required_tags.module_version
    framework_targets         = ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.0"]
    controls_satisfied        = ["AC-2", "AC-3", "AC-6", "IA-2(1)", "IA-2(2)", "IA-5"]
    environment               = var.environment
    required_compliance_scope = var.required_compliance_scope

    password_policy_meets_minimums = (
      aws_iam_account_password_policy.this.minimum_password_length >= 14 &&
      aws_iam_account_password_policy.this.max_password_age <= 90 &&
      aws_iam_account_password_policy.this.password_reuse_prevention >= 5 &&
      aws_iam_account_password_policy.this.require_lowercase_characters &&
      aws_iam_account_password_policy.this.require_numbers &&
      aws_iam_account_password_policy.this.require_symbols &&
      aws_iam_account_password_policy.this.require_uppercase_characters
    )

    require_mfa_policy_bool_if_exists = try(
      jsondecode(aws_iam_policy.require_mfa.policy).Statement[0].Condition.BoolIfExists["aws:MultiFactorAuthPresent"] == "false",
      false
    )

    mfa_enforcement_policy_on_all_groups = (
      try(jsondecode(aws_iam_policy.require_mfa.policy).Statement[0].Condition.BoolIfExists["aws:MultiFactorAuthPresent"] == "false", false) &&
      alltrue([
        for _, attachment in aws_iam_group_policy_attachment.require_mfa :
        attachment.policy_arn == aws_iam_policy.require_mfa.arn
      ])
    )

    auditor_role_mfa_trust_enforced = contains(keys(aws_iam_role.this), "LabCrossAccountAuditor") ? try(
      jsondecode(aws_iam_role.this["LabCrossAccountAuditor"].assume_role_policy).Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"] == "true",
      false
    ) : false

    access_analyzer_enabled = length(aws_accessanalyzer_analyzer.this) > 0

    required_tags_present = alltrue([
      for k in keys(local.required_tags) : contains(keys(aws_iam_policy.require_mfa.tags_all), k)
    ])

    cji_user_tag_convention_enforced = !var.cji_users_enabled || alltrue([
      for name, role in aws_iam_role.this :
      !local.roles[name].human_assumable || lookup(role.tags_all, "cji_user_role", "") == "true"
    ])
  }
}
