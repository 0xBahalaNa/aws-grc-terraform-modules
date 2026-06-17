# Module: iam-hardening

Lab 1 module (v1.1.1). IAM baseline aligned with NIST 800-53 Rev 5 **AC-2 / AC-3 / AC-6**, **IA-2(1)(2)**, and **IA-5**, with CJIS v6.0 **IA-2 AAL2** (MFA on trust policy) and **CJI-user tagging** deltas.

> **Status: v1.1.1 implemented.** Password policy, `RequireMFA` deny policy, baseline groups, `Lab*` roles, and account Access Analyzer. Companion Console walkthrough on [luigicarpio.dev/blog](https://luigicarpio.dev/blog). Permissions boundaries are **deferred** to `aws-compliance-as-code` — not in this module.

## What This Module Creates

| Lab step | Resource | Control |
|---|---|---|
| 1 | `aws_iam_account_password_policy` | IA-5 / IA-5(1) |
| 3 | `aws_iam_policy` (`RequireMFA`) + group attachments | IA-2(1), IA-2(2) |
| 4 | `aws_iam_group` ×3 + managed policy attachments | AC-2, AC-3, AC-6 |
| 5 | `aws_iam_role` ×3 (auditor MFA trust, EC2, Lambda) | AC-2, IA-2 |
| 6 | `aws_accessanalyzer_analyzer` (optional) | CA-7 continuous monitoring (RA-5/AC-6 supporting) |

**Scope limits (honest framing):**

- **No `aws_iam_user` resources** — users and group memberships are out of module scope (console/lifecycle managed).
- **`lab-admins` default includes `AdministratorAccess`** — this mirrors the Lab 1 console baseline (MFA-gated via `RequireMFA`), not production least-privilege. Tighten `var.groups` for real workloads.
- **RequireMFA attaches to groups only** — governs principals once they are group members; module does not assign users.

## Controls Addressed

| NIST 800-53 Rev 5 | FedRAMP High | CJIS v6.0 | How This Module Enforces It |
|---|---|:---:|---|
| AC-2 (Account Management) | Yes | 5.5.x delta | Group-based access model; optional `cji_user_role` tag on human-assumable roles |
| AC-3 (Access Enforcement) | Yes | Policy Area 5 | Role trust policies; RequireMFA deny on group members |
| AC-6 (Least Privilege) | Yes | Policy Area 5 | Tiered group grants (admin/dev/auditor); MFA gate on all group permissions |
| IA-2(1)(2) (MFA) | Yes | IA-2 AAL2 | `BoolIfExists` on `aws:MultiFactorAuthPresent`; auditor role trust requires MFA |
| IA-5 (Authenticator Management) | Yes | Policy Area 6 | Account password policy (14-char, complexity, 90-day, reuse 5) |

## Brownfield / Import

If you built Lab 1 in the Console first (same account), `terraform apply` will conflict on fixed names (`RequireMFA`, `lab-admins`, `lab-account-analyzer`, etc.). Options:

1. **Import** existing resources into Terraform state, or
2. Set `enable_access_analyzer = false` if an analyzer already exists, and customize `access_analyzer_name` / group names via variables.

See [Terraform import](https://developer.hashicorp.com/terraform/cli/import).

## Compliance Attestation Output

Self-verifying booleans read **deployed resource attributes** (not inputs):

```json
{
  "module": "iam-hardening",
  "module_version": "1.1.1",
  "framework_targets": ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.0"],
  "controls_satisfied": ["AC-2", "AC-3", "AC-6", "IA-2(1)", "IA-2(2)", "IA-5"],
  "password_policy_meets_minimums": true,
  "require_mfa_policy_bool_if_exists": true,
  "mfa_enforcement_policy_on_all_groups": true,
  "auditor_role_mfa_trust_enforced": true,
  "access_analyzer_enabled": true,
  "required_tags_present": true,
  "cji_user_tag_convention_enforced": true
}
```

## Usage

```hcl
module "iam_baseline" {
  source = "git::https://github.com/0xBahalaNa/aws-grc-terraform-modules.git//modules/iam-hardening?ref=v1.1.1"

  environment               = "dev"
  project_tag               = "lab-1-iam-hardening"
  required_compliance_scope = "fedramp-high"
  cji_users_enabled         = true
}

output "iam_compliance_evidence" {
  value = module.iam_baseline.compliance_attestation
}
```

Pin `?ref=` to a tagged release for reproducible builds.

## Examples

Runnable caller under `examples/basic/` — init, validate, and plan from that directory:

```bash
cd modules/iam-hardening/examples/basic
terraform init
terraform validate
# Set AWS_REGION or a default region in ~/.aws/config before plan.
terraform plan
```

Plan before apply. Brownfield accounts with existing Lab 1 resources may need import or non-prod `enable_access_analyzer = false`.

## Roadmap

- **v1.1.0:** Lab 1 baseline resources + self-verifying attestation
- **v1.1.1 (shape pass):** Lab 2.3 control comments, prod Access Analyzer validation, `examples/basic/`
- **v1.2.0:** OPA/Rego policy bundle + CI `conftest test` (chassis)
- **v1.3.0:** terraform-docs drift check

## License

MIT. See parent repo `LICENSE.txt`.
