# iam-hardening — Lab 1 module (v1.1.1)
#
# Codifies Lab 1 console baseline: password policy, RequireMFA deny policy,
# baseline groups, Lab* roles (MFA-conditioned auditor trust), Access Analyzer.
# Permissions boundaries deferred to aws-compliance-as-code.
# Companion walkthrough: luigicarpio.dev/blog

# Required compliance tags layered on top of consumer-provided tags.
# Argument order is deliberate — required tags overwrite consumer attempts to
# suppress them. This is the CM-3 enforcement primitive every module reuses.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  required_tags = {
    compliance_scope = var.required_compliance_scope
    project          = var.project_tag
    environment      = var.environment
    managed_by       = "aws-grc-terraform-modules/iam-hardening"
    framework_target = "FedRAMP-High,CJIS-v6.0,NIST-800-53-Rev-5"
    module_version   = "1.1.1"
  }

  merged_tags = merge(var.tags, local.required_tags)
  groups      = { for g in var.groups : g.name => g }
  roles       = { for r in var.roles : r.name => r }

  require_mfa_policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyAllExceptUnlessMFAPresent"
      Effect = "Deny"
      NotAction = [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetAccountPasswordPolicy",
        "iam:GetMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListUsers",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "iam:ChangePassword",
        "sts:GetSessionToken",
      ]
      Resource = "*"
      Condition = {
        BoolIfExists = {
          "aws:MultiFactorAuthPresent" = "false"
        }
      }
    }]
  })

  default_role_trust_policies = {
    LabCrossAccountAuditor = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid       = "AllowAccountRootWithMFA"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
      }]
    })
    LabEC2InstanceProfile = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }]
    })
    LabLambdaExecutionRole = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }]
    })
  }

  group_managed_attachments = {
    for a in flatten([
      for g in var.groups : [
        for arn in g.managed_policies : {
          key = "${g.name}/${arn}", group_name = g.name, policy_arn = arn
        }
      ]
    ]) : a.key => a
  }

  group_custom_policies = {
    for p in flatten([
      for g in var.groups : [
        for name, doc in g.custom_policy_jsons : {
          key = "${g.name}/${name}", group_name = g.name, policy_name = name, policy_doc = doc
        }
      ]
    ]) : p.key => p
  }

  role_policy_attachments = {
    for a in flatten([
      for r in var.roles : [
        for arn in r.attached_policies : {
          key = "${r.name}/${arn}", role_name = r.name, policy_arn = arn
        }
      ]
    ]) : a.key => a
  }

  role_tags = {
    for name, role in local.roles : name => merge(
      local.merged_tags,
      role.human_assumable && var.cji_users_enabled ? { cji_user_role = "true" } : {},
    )
  }
}

# IA-5 — Account password policy (authenticator strength / rotation)
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length      = var.password_policy.minimum_password_length
  require_lowercase_characters = var.password_policy.require_lowercase_characters
  require_numbers              = var.password_policy.require_numbers
  require_symbols              = var.password_policy.require_symbols
  require_uppercase_characters = var.password_policy.require_uppercase_characters
  max_password_age             = var.password_policy.max_password_age
  password_reuse_prevention    = var.password_policy.password_reuse_prevention
}

# IA-2(1)(2) — RequireMFA deny policy (BoolIfExists on aws:MultiFactorAuthPresent)
resource "aws_iam_policy" "require_mfa" {
  name        = "RequireMFA"
  description = "Deny all actions unless MFA is present (BoolIfExists on aws:MultiFactorAuthPresent)."
  policy      = local.require_mfa_policy_document
  tags        = local.merged_tags
}

# AC-2 — Baseline IAM groups (account management / role separation)
resource "aws_iam_group" "this" {
  for_each = local.groups
  name     = each.key
}

# IA-2(1)(2) — Attach RequireMFA to every group member principal
resource "aws_iam_group_policy_attachment" "require_mfa" {
  for_each   = aws_iam_group.this
  group      = each.value.name
  policy_arn = aws_iam_policy.require_mfa.arn
}

# AC-6 — Tiered managed-policy grants per group (least privilege)
resource "aws_iam_group_policy_attachment" "managed" {
  for_each   = local.group_managed_attachments
  group      = aws_iam_group.this[each.value.group_name].name
  policy_arn = each.value.policy_arn
}

# AC-6 — Custom inline policies scoped to group tier
resource "aws_iam_policy" "group_custom" {
  for_each = local.group_custom_policies
  name     = "ih-${substr(sha256(each.key), 0, 12)}"
  policy   = each.value.policy_doc
  tags     = local.merged_tags
}

# AC-6 — Bind custom policies to groups
resource "aws_iam_group_policy_attachment" "group_custom" {
  for_each   = aws_iam_policy.group_custom
  group      = aws_iam_group.this[local.group_custom_policies[each.key].group_name].name
  policy_arn = each.value.arn
}

# AC-2 / IA-2 — Baseline IAM roles with MFA-conditioned trust where applicable
resource "aws_iam_role" "this" {
  for_each = local.roles
  name     = each.key
  assume_role_policy = coalesce(
    each.value.trust_policy_json,
    lookup(local.default_role_trust_policies, each.key, null),
  )
  tags = local.role_tags[each.key]
}

# AC-6 — Least-privilege policy attachments per role
resource "aws_iam_role_policy_attachment" "this" {
  for_each   = local.role_policy_attachments
  role       = aws_iam_role.this[each.value.role_name].name
  policy_arn = each.value.policy_arn
}

# AC-2 — EC2 instance profile for LabEC2InstanceProfile role
resource "aws_iam_instance_profile" "this" {
  for_each = { for name, role in local.roles : name => role if role.create_instance_profile }
  name     = each.key
  role     = aws_iam_role.this[each.key].name
  tags     = local.merged_tags
}


# CA-7 — Account IAM Access Analyzer (detective external-access monitoring; RA-5 supporting, AC-6 informing)
resource "aws_accessanalyzer_analyzer" "this" {
  count         = var.enable_access_analyzer ? 1 : 0
  analyzer_name = var.access_analyzer_name
  type          = "ACCOUNT"
  tags          = local.merged_tags
}

