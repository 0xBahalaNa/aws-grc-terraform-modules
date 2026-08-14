# Module: s3-compliant-bucket

Lab 2 module (v1.2.1). Evidence bucket aligned with NIST 800-53 Rev 5 **SC-28 / SC-28(1)**, **SC-13**, **SC-8**, **AC-3 / AC-6**, **AU-11**, **AU-9**, **SI-7 / CP-9**, and **CM-6**, with CJIS v6.1 deltas (agency-managed CMK; 1-year Object Lock retention).

> **Status: v1.2.1 implemented.** SSE-KMS with a required customer-managed CMK, Object Lock Governance (365-day floor), versioning, bucket-level Block Public Access, TLS-only bucket policy, optional server access logging to a consumer-supplied bucket, and one noncurrent-version lifecycle rule. Companion Console walkthrough: [luigicarpio.dev/blog/2026-07-aws-lab-2-s3-compliant-bucket](https://luigicarpio.dev/blog/2026-07-aws-lab-2-s3-compliant-bucket). OPA/Rego policy bundle is **deferred** to the chassis minor — not in this module.

## What This Module Creates

| Resource | Control |
|---|---|
| `aws_s3_bucket` | SC-28, AC-3 |
| `aws_s3_bucket_server_side_encryption_configuration` | SC-28, SC-28(1), SC-13 |
| `aws_s3_bucket_versioning` | SI-7, CP-9 |
| `aws_s3_bucket_object_lock_configuration` | AU-11 |
| `aws_s3_bucket_public_access_block` | AC-3, AC-6 |
| `aws_s3_bucket_policy` | SC-8 |
| `aws_s3_bucket_logging` (optional) | AU-9 |
| `aws_s3_bucket_lifecycle_configuration` | CP-9, AU-11 |
| `aws_s3_account_public_access_block` (optional) | AC-3, AC-6 |

**Scope limits (honest framing):**

- **The access-logs bucket is not created here.** S3 log delivery won't write to a destination with SSE-KMS or Object Lock, and this bucket has both. AU-9 coverage means "logging is wired to your log bucket" — bring your own.

- **`kms_cmk_arn` validation checks shape, not ownership.** The regex requires a `key/` ARN (aliases fail, GovCloud passes) but doesn't check `KeyManager`, so an AWS-managed key ARN slips through. See [variable validation](https://developer.hashicorp.com/terraform/language/block/variable#custom-validation-rules) and [key vs alias ARNs](https://docs.aws.amazon.com/kms/latest/developerguide/find-cmk-id-arn.html).

- **Object Lock runs in GOVERNANCE mode.** Retention can be shortened by anyone with `s3:BypassGovernanceRetention`; COMPLIANCE can't be, even by root. See [retention modes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-overview.html).

- **`manage_account_defaults` goes true on exactly one module call.** Account-level Block Public Access is one resource per account; defaults to `false`. EBS encryption-by-default was dropped — it forces the AWS-managed `aws/ebs` key, which this repo forbids. EBS CMK is Lab 7.

## Controls Addressed

| NIST 800-53 Rev 5 | FedRAMP High | CJIS v6.1 | How This Module Enforces It |
|---|:---:|:---:|---|
| SC-28 / SC-28(1) (Protection of Information at Rest) | Yes | P2 — agency-managed CMK delta | SSE-KMS default encryption; required `key/` CMK ARN; `blocked_encryption_types = ["SSE-C"]` |
| SC-13 (Cryptographic Protection) | Yes | P2 — agency-managed CMK delta | Customer-managed CMK only. GovCloud `arn:aws-us-gov:kms:…:key/…` passes the regex (FIPS endpoints annotated, not deployed) |
| SC-8 (Transmission Confidentiality and Integrity) | Yes | P2 — encryption in transit | TLS-only bucket policy: Deny when `aws:SecureTransport` is `"false"` |
| AC-3 / AC-6 (Access Enforcement / Least Privilege) | Yes | P1 | All four Block Public Access flags hardcoded; account-level BPA is an optional singleton |
| AU-11 (Audit Record Retention) | Yes | P4 — 1-yr retention delta | Object Lock GOVERNANCE default 365 days; lifecycle expiration cannot undercut it |
| AU-9 (Protection of Audit Information) | Yes | P2 | Server access logging to a consumer-supplied destination (count-gated) |
| SI-7 / CP-9 (Integrity / System Backup) | Yes | P1 / P2 | Versioning forced on; noncurrent versions transition to GLACIER then expire |
| CM-6 (Configuration Settings) | Yes | P1 | Required tags via `merge(var.tags, local.required_tags)`; fail-closed defaults |

## Requirements

- Terraform >= 1.9 — cross-variable validation (`logs_destination_bucket` when logging is on; `noncurrent_expiration_days` must not undercut Object Lock). See [cross-object validation](https://developer.hashicorp.com/terraform/language/block/variable#cross-object-validation-conditions).
- AWS provider >= 6.22.0 — `blocked_encryption_types` on the encryption resource (the console's BlockedEncryptionTypes: SSE-C).

## Compliance Attestation Output

Self-verifying booleans read **deployed resource attributes** (not inputs). Sample as `examples/basic` would produce it (`manage_account_defaults` stays false):

```json
{
  "module": "s3-compliant-bucket",
  "module_version": "1.2.1",
  "framework_targets": ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.1"],
  "controls_satisfied": ["SC-28", "SC-28(1)", "SC-8", "AC-3", "AC-6", "CP-9", "SI-7", "AU-11", "AU-9"],
  "environment": "dev",
  "required_compliance_scope": "fedramp-high",
  "sse_kms_with_cmk": true,
  "bucket_key_enabled": true,
  "versioning_enabled": true,
  "object_lock_governance_1yr": true,
  "tls_only_policy_attached": true,
  "block_public_access_all_enabled": true,
  "access_logging_enabled": true,
  "required_tags_present": true,
  "account_defaults_managed": false
}
```

## Usage

```hcl
module "evidence_bucket" {
  source = "git::https://github.com/0xBahalaNa/aws-grc-terraform-modules.git//modules/s3-compliant-bucket?ref=v1.2.1"

  bucket_name               = "grc-lab2-evidence"
  kms_cmk_arn               = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  environment               = "dev"
  project_tag               = "lab-2-s3-compliant-bucket"
  logs_destination_bucket   = "grc-lab2-access-logs"
}
```

Pin `?ref=` to a tagged release. `kms_cmk_arn` must be a customer-managed `key/` ARN — not `alias/aws/s3`.

## Examples

Runnable caller under `examples/basic/`. From the repo root:

```bash
cd modules/s3-compliant-bucket/examples/basic && terraform init && terraform validate
```

`validate` needs no AWS credentials. `terraform plan` needs credentials, a region (`AWS_REGION` or `~/.aws/config`), and the placeholder CMK ARN replaced with a real customer-managed key.

## Roadmap

- **v1.2.0:** Lab 2 core (bucket, SSE-KMS, Object Lock, BPA, TLS policy, logging, lifecycle, attestation)
- **v1.2.1 (this):** README, `examples/basic/`, inline attestation sample
- **Chassis minor:** OPA/Rego policy bundle + CI gates

## License

MIT. See parent repo `LICENSE`.
