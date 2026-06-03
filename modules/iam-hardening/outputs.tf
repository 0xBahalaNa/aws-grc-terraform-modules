# compliance_attestation — the canonical evidence output every module in this
# repo emits. Consumed by oscal-evidence-pipeline as a Component Definition
# implemented-requirement evidence URI.
#
# IMPORTANT: In the v0.1.0 scaffold, the per-control booleans below are
# placeholders that read from variable inputs. In the Lab 1 implementation PR,
# each boolean is replaced with a read against actual deployed resource state
# (e.g., parsing aws_iam_role.admin.assume_role_policy for the
# aws:MultiFactorAuthPresent condition key). This is what makes the attestation
# self-verifying — the module cannot claim a control is satisfied; it computes
# whether the deployed state matches the control requirement.

output "compliance_attestation" {
  description = "Self-verifying compliance attestation for this module. Consumed by oscal-evidence-pipeline as evidence input."
  value = {
    module                           = "iam-hardening"
    module_version                   = local.required_tags.module_version
    framework_targets                = ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.0"]
    controls_satisfied               = ["AC-2", "AC-3", "AC-6", "IA-2(1)", "IA-2(2)", "IA-5"]
    cjis_v6_deltas_addressed         = var.cji_users_enabled ? ["5.5.x — CJI-user tag convention", "IA-2 AAL2 — MFA on trust policy"] : []
    environment                      = var.environment
    required_compliance_scope        = var.required_compliance_scope

    # Per-control booleans — placeholders. Implementation PR replaces these
    # with attribute reads against deployed resources.
    mfa_required_on_admin_role_trust_policy = false
    permission_boundary_attached_to_admin   = false
    service_role_separated_from_admin       = false
    cji_user_tag_convention_enforced        = var.cji_users_enabled
    required_tags_present                   = true
  }
}
