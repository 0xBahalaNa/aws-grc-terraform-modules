variable "environment" {
  description = "Deployment environment. Used for plan-time validation of compliance contracts (e.g., production CJIS-retention enforcement)."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "project_tag" {
  description = "Project identifier applied as the `project` tag on all module resources."
  type        = string
}

variable "required_compliance_scope" {
  description = "Compliance baseline this module is enforcing for. Drives the `compliance_scope` tag and which controls appear in the attestation output."
  type        = string
  default     = "fedramp-high"

  validation {
    condition     = contains(["fedramp-high", "cjis-v6", "nist-800-53-rev-5"], var.required_compliance_scope)
    error_message = "required_compliance_scope must be one of: fedramp-high, cjis-v6, nist-800-53-rev-5."
  }
}

variable "cji_users_enabled" {
  description = "Enforce the CJIS v6.0 AC-2 delta CJI-user tagging convention. When true, human-assumable roles carry a `cji_user_role` tag that downstream quarterly access-review automation can filter on."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Consumer-provided tags. Merged via `merge(var.tags, local.required_tags)` so the module's compliance tags overwrite any consumer attempts to suppress them."
  type        = map(string)
  default     = {}
}

variable "password_policy" {
  description = "Account password policy settings. Defaults match Lab 1 console baseline (IA-5 / IA-5(1))."
  type = object({
    minimum_password_length      = number
    require_lowercase_characters = bool
    require_numbers              = bool
    require_symbols              = bool
    require_uppercase_characters = bool
    max_password_age             = number
    password_reuse_prevention    = number
  })
  default = {
    minimum_password_length      = 14
    require_lowercase_characters = true
    require_numbers              = true
    require_symbols              = true
    require_uppercase_characters = true
    max_password_age             = 90
    password_reuse_prevention    = 5
  }
  validation {
    condition = (
      var.password_policy.max_password_age <= 90 &&
      var.password_policy.minimum_password_length >= 14
    )
    error_message = "password_policy must enforce max_password_age <= 90 and minimum_password_length >= 14 (FedRAMP High / CJIS IA-5 minimums)."
  }
}

variable "groups" {
  description = "Baseline IAM groups. RequireMFA is attached to every group by the module."
  type = list(object({
    name                = string
    managed_policies    = list(string)
    custom_policy_jsons = optional(map(string), {})
  }))
  default = [
    { name = "lab-admins", managed_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"] },
    { name = "lab-developers", managed_policies = ["arn:aws:iam::aws:policy/PowerUserAccess"] },
    { name = "lab-auditors", managed_policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"] },
  ]
}

variable "roles" {
  description = "Baseline IAM roles from Lab 1 step 5. Null trust_policy_json uses module-built trust for Lab* names."
  type = list(object({
    name                    = string
    trust_policy_json       = optional(string)
    attached_policies       = list(string)
    create_instance_profile = optional(bool, false)
    human_assumable         = optional(bool, false)
  }))
  default = [
    {
      name              = "LabCrossAccountAuditor"
      attached_policies = ["arn:aws:iam::aws:policy/SecurityAudit"]
      human_assumable   = true
    },
    {
      name                    = "LabEC2InstanceProfile"
      attached_policies       = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
      create_instance_profile = true
    },
    {
      name              = "LabLambdaExecutionRole"
      attached_policies = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    },
  ]

  validation {
    condition = alltrue([
      for r in var.roles : (
        contains(["LabCrossAccountAuditor", "LabEC2InstanceProfile", "LabLambdaExecutionRole"], r.name) ||
        r.trust_policy_json != null
      )
    ])
    error_message = "Custom role names must set trust_policy_json. Module-built trust applies only to LabCrossAccountAuditor, LabEC2InstanceProfile, and LabLambdaExecutionRole."
  }
}

variable "enable_access_analyzer" {
  description = "Create account-level IAM Access Analyzer (Lab 1 step 6)."
  type        = bool
  default     = true

  validation {
    condition     = var.environment != "prod" || var.enable_access_analyzer
    error_message = "Access Analyzer cannot be disabled in prod (CM-6 baseline config / CA-7 continuous-monitoring continuity)."
  }
}

variable "access_analyzer_name" {
  description = "Name for the account Access Analyzer. One ACCOUNT analyzer per account/region — import existing analyzers or set enable_access_analyzer=false on brownfield accounts."
  type        = string
  default     = "lab-account-analyzer"
}