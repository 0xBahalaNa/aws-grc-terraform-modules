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
