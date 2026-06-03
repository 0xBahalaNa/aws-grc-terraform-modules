# Module: iam-hardening

Lab 1 module. IAM baseline aligned with NIST 800-53 Rev 5 **AC-2 / AC-3 / AC-6**, **IA-2(1)(2)**, and **IA-5**, with the CJIS v6.0 **AAL2** (MFA on trust policy) and **agency-managed-CMK** / **CJI-user tagging** deltas layered on top where the framework exceeds FedRAMP High.

> **Status: v0.1.0 SCAFFOLD.** Variable contracts, required-tag merging, and the `compliance_attestation` output structure are in place. Resource implementations (admin role with MFA-required trust policy, permissions boundary, separated service role, account password policy) land per the Lab 1 implementation PR (~2026-06-30). Companion Console walkthrough on [luigicarpio.dev/blog](https://luigicarpio.dev/blog).

## Controls Addressed

| NIST 800-53 Rev 5 | FedRAMP High | CJIS v6.0 | How This Module Enforces It |
|---|:---:|:---:|---|
| AC-2 (Account Management) | Yes | Policy Area 5 + CJI-user delta | Tag convention; CJI-flagged roles emitted as separate `aws_iam_role` resources |
| AC-3 (Access Enforcement) | Yes | Policy Area 5 | Role trust policies + resource-scoped inline policies |
| AC-6 / AC-6(9) (Least Privilege) | Yes | Policy Area 5 | Permissions boundary on every human-assumable role |
| IA-2(1)(2) (MFA) | Yes | IA-2 AAL2 delta | `aws:MultiFactorAuthPresent` condition required in admin trust policy |
| IA-5 (Authenticator Management) | Yes | Policy Area 6 | `aws_iam_account_password_policy` enforces length / complexity / rotation |

## Compliance Attestation Output

This module emits a `compliance_attestation` output that downstream consumers (e.g., [`oscal-evidence-pipeline`](https://github.com/0xBahalaNa/oscal-evidence-pipeline)) cite as evidence. The attestation is **self-verifying** — each per-control boolean reads from actual deployed resource state (not from input variables) once the implementation PR lands.

Example output shape (final implementation):

```json
{
  "module": "iam-hardening",
  "module_version": "0.1.0",
  "framework_targets": ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.0"],
  "controls_satisfied": ["AC-2", "AC-3", "AC-6", "IA-2(1)", "IA-2(2)", "IA-5"],
  "cjis_v6_deltas_addressed": [
    "5.5.x — CJI-user tag convention",
    "IA-2 AAL2 — MFA on trust policy"
  ],
  "mfa_required_on_admin_role_trust_policy": true,
  "permission_boundary_attached_to_admin": true,
  "service_role_separated_from_admin": true,
  "cji_user_tag_convention_enforced": true,
  "required_tags_present": true
}
```

## Usage (Once Implemented)

```hcl
module "iam_baseline" {
  source = "git::https://github.com/0xBahalaNa/aws-grc-terraform-modules.git//modules/iam-hardening?ref=v1.1.0"

  environment               = "prod"
  project_tag               = "compliance-as-code"
  required_compliance_scope = "fedramp-high"
  cji_users_enabled         = true
}

output "iam_compliance_evidence" {
  value = module.iam_baseline.compliance_attestation
}
```

Pin `?ref=` to a tagged release for reproducible builds.

## Roadmap

- **v0.1.0 (this commit):** scaffold — variable contracts + tag merging + attestation output structure
- **v1.1.0 (Lab 1 implementation PR, ~2026-06-30):** admin role + permissions boundary + service role + password policy + per-control attribute reads in `compliance_attestation`
- **v1.2.0:** OPA/Rego policy bundle (`policy/iam-hardening.rego` + `policy/iam-hardening_test.rego`) wired into CI via `conftest test`
- **v1.3.0:** `examples/basic/` end-to-end consumer scenario; `terraform-docs` drift check enabled

## License

MIT. See parent repo `LICENSE.txt`.
