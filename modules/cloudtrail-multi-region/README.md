# Module: cloudtrail-multi-region

Lab 4 module (v1.4.0). The account's audit trail, aligned with NIST 800-53 Rev 5 **AU-2 / AU-3 / AU-12** (what gets logged), **AU-9** (signed digests and SSE-KMS), **AU-11** (1-year retention on the CloudWatch Logs copy), and **SI-4** (alerting on root activity, console login without MFA, and IAM policy changes).

> **Status: v1.4.0 in progress, PR 2 of 3 (alerting).** PR 1 built collection: one multi-region trail to an existing Lab 2 bucket, its CloudWatch Logs group, and the role CloudTrail uses to write there. This PR adds alerting (metric filters, alarms, EventBridge rules). PR 3 adds Athena. All three land in this same v1.4.0 before it is tagged. Companion walkthrough: [luigicarpio.dev/labs/2026-11-aws-lab-4-cloudtrail-audit](https://luigicarpio.dev/labs/2026-11-aws-lab-4-cloudtrail-audit/). OPA/Rego policy bundle is **deferred** to the chassis minor, same call as Labs 2 and 3.

## What This Module Creates

| Resource | Control |
|---|---|
| `aws_cloudtrail`: multi-region, log file validation on, global service events on, SSE-KMS with the CMK, management events Read + Write | AU-2, AU-3, AU-9, AU-12 |
| `aws_cloudwatch_log_group` `/aws/cloudtrail/<prefix>-trail`, 365-day retention, CMK-encrypted | AU-11 |
| `aws_iam_role` `CloudTrailRole-<prefix>`, trust pinned to the trail with `aws:SourceArn` | AC-6 |
| `aws_iam_role_policy` `cloudtrail-to-cwlogs`: `CreateLogStream` + `PutLogEvents` on this group's streams only | AC-6 |
| 3 `aws_cloudwatch_log_metric_filter`: `RootActivity`, `ConsoleLoginNoMFA`, `IAMPolicyChange` in namespace `GRC/Lab4` (CIS patterns) | SI-4 |
| 3 `aws_cloudwatch_metric_alarm`: `<prefix>-root-activity`, `<prefix>-console-login-no-mfa`, `<prefix>-iam-policy-change`. Sum >= 1 over 5 minutes, missing data `notBreaching` | SI-4 |
| 3 `aws_cloudwatch_event_rule` on the default bus with the same names, plus 3 `aws_cloudwatch_event_target` (target ID `sns`) | SI-4 |

There is no `is_multi_region_trail` or `enable_log_file_validation` input. Both are literal `true` in `main.tf`. A caller cannot turn either off because there is no variable to set.

With the default `name_prefix = "grc-lab4"` the names match the Lab 4 CLI build: trail `grc-lab4-trail`, log group `/aws/cloudtrail/grc-lab4-trail`, role `CloudTrailRole-grc-lab4`, inline policy `cloudtrail-to-cwlogs`, alarms and EventBridge rules `grc-lab4-root-activity`, `grc-lab4-console-login-no-mfa`, `grc-lab4-iam-policy-change`.

**Scope limits:**

- **Logs stay in the account they describe.** AU-9(2) wants audit records on a separate system. The production answer is an organization trail delivering to a log-archive account. I built a single-account trail because the lab org has one account. AU-9(2) is not met.
- **The WORM control is the Lab 2 bucket's, and it is GOVERNANCE mode.** An admin with `s3:BypassGovernanceRetention` can delete a locked log file. COMPLIANCE mode closes that and also makes the bucket impossible to clean up in a lab.
- **Management events only.** No S3 or Lambda data events, no Insights events. Adding either later is a minor version.
- **One trail per account and region by name.** A second copy with the same `name_prefix` collides.
- **The module does not write the bucket policy or the key policy.** Both belong to the Lab 2 stack. The next section lists what the caller adds by hand.
- **The module does not create the SNS topic, its subscriptions, or its policy.** The lab topic is unencrypted. Encrypting it with the CMK needs two more key-policy statements, one for `events.amazonaws.com` and one for `cloudwatch.amazonaws.com`. The AWS-managed `aws/sns` key can't admit EventBridge. Alert bodies carry event metadata, not CJI.
- **EventBridge rules are regional.** They cover only the module's region. The alarm path covers every region because the one log group carries the whole trail.
- **`notBreaching` hides a dead pipeline.** An alarm can't tell no events from no pipeline. Pipeline health is `get-trail-status`, not the alarm state.

## Policies the caller adds before apply

Swap `<ACCOUNT_ID>`, `<REGION>` (the trail's home region), `<TRAIL_NAME>` (`<prefix>-trail`), and `<BUCKET>`. In GovCloud every ARN uses the `aws-us-gov` partition.

The trail name has to agree in three places: the trail itself, the key policy's `aws:SourceArn`, and the bucket policy's `aws:SourceArn`. If one of them is wrong, CloudTrail accepts the configuration and delivers nothing. Plan and validate cannot catch it. `get-trail-status` can.

CMK key policy, four statements. The account-root `kms:*` statement does not cover either service principal.

```json
{
  "Sid": "AllowCloudTrailEncryptLogs",
  "Effect": "Allow",
  "Principal": { "Service": "cloudtrail.amazonaws.com" },
  "Action": "kms:GenerateDataKey*",
  "Resource": "*",
  "Condition": {
    "StringEquals": { "aws:SourceArn": "arn:aws:cloudtrail:<REGION>:<ACCOUNT_ID>:trail/<TRAIL_NAME>" },
    "StringLike": { "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:<ACCOUNT_ID>:trail/*" }
  }
},
{
  "Sid": "AllowCloudTrailDescribeKey",
  "Effect": "Allow",
  "Principal": { "Service": "cloudtrail.amazonaws.com" },
  "Action": "kms:DescribeKey",
  "Resource": "*",
  "Condition": {
    "StringEquals": { "aws:SourceArn": "arn:aws:cloudtrail:<REGION>:<ACCOUNT_ID>:trail/<TRAIL_NAME>" }
  }
},
{
  "Sid": "AllowCloudTrailDecryptTrail",
  "Effect": "Allow",
  "Principal": { "Service": "cloudtrail.amazonaws.com" },
  "Action": "kms:Decrypt",
  "Resource": "*"
},
{
  "Sid": "AllowCloudWatchLogsUsage",
  "Effect": "Allow",
  "Principal": { "Service": "logs.<REGION>.amazonaws.com" },
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"],
  "Resource": "*",
  "Condition": {
    "ArnLike": { "kms:EncryptionContext:aws:logs:arn": "arn:aws:logs:<REGION>:<ACCOUNT_ID>:log-group:*" }
  }
}
```

`AllowCloudTrailDecryptTrail` is needed only when the bucket has S3 Bucket Key on, which `s3-compliant-bucket` does. It is unconditioned because that is the shape AWS documents. The CloudWatch Logs statement conditions on the encryption context, not `aws:SourceAccount`, because CloudWatch Logs does not set `aws:SourceAccount`.

Bucket policy, two statements. Merge them under the existing `DenyInsecureTransport` statement and apply the merged policy by hand, same as Lab 3.

```json
{
  "Sid": "AWSCloudTrailAclCheck",
  "Effect": "Allow",
  "Principal": { "Service": "cloudtrail.amazonaws.com" },
  "Action": "s3:GetBucketAcl",
  "Resource": "arn:aws:s3:::<BUCKET>",
  "Condition": {
    "StringEquals": { "aws:SourceArn": "arn:aws:cloudtrail:<REGION>:<ACCOUNT_ID>:trail/<TRAIL_NAME>" }
  }
},
{
  "Sid": "AWSCloudTrailWrite",
  "Effect": "Allow",
  "Principal": { "Service": "cloudtrail.amazonaws.com" },
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::<BUCKET>/AWSLogs/<ACCOUNT_ID>/*",
  "Condition": {
    "StringEquals": {
      "s3:x-amz-acl": "bucket-owner-full-control",
      "aws:SourceArn": "arn:aws:cloudtrail:<REGION>:<ACCOUNT_ID>:trail/<TRAIL_NAME>"
    }
  }
}
```

The same drift limit as Lab 3 applies. `s3-compliant-bucket` has no input for extra statements, so the next apply of the bucket stack reverts its policy and delivery stops.

Object Lock does not block CloudTrail delivery. I proved it on 2026-11-22: the first log file landed under GOVERNANCE default retention with both delivery-error fields empty.

SNS topic policy, one statement.

```json
{
  "Sid": "AllowEventBridgePublish",
  "Effect": "Allow",
  "Principal": { "Service": "events.amazonaws.com" },
  "Action": "sns:Publish",
  "Resource": "arn:aws:sns:<REGION>:<ACCOUNT_ID>:<TOPIC_NAME>",
  "Condition": {
    "ArnLike": { "aws:SourceArn": "arn:aws:events:<REGION>:<ACCOUNT_ID>:rule/<PREFIX>-*" }
  }
}
```

Keep the topic's `__default_statement_ID`. The alarms publish through it, because CloudWatch alarms in the same account publish as the account (`AWS:SourceOwner`). The CLI and Terraform do not add the EventBridge statement the console adds. Without it the rules match and the publish fails silently; only the rule's `FailedInvocations` metric shows it. The `aws:SourceArn` condition was proven on 2026-11-22: the alert test delivered both EventBridge emails.

## Controls Addressed

| NIST 800-53 Rev 5 | FedRAMP High | CJIS v6.1 | How This Module Enforces It |
|---|:---:|:---:|---|
| AU-2 / AU-3 / AU-12 (Event Logging / Content / Generation) | Yes | AU-2, AU-3, AU-12 | Multi-region trail, management events Read + Write, global service events on. No off switch |
| AU-9 (Protection of Audit Information) | Yes | AU-9 | Log file validation (hourly signed digests) and SSE-KMS with the agency-managed CMK. Object Lock is inherited from the Lab 2 bucket |
| AU-11 (Audit Record Retention) | Yes | 1-year retention | CloudWatch Logs retention 365 days minimum, enforced by validation. The S3 copy's retention is the Lab 2 bucket's Object Lock default |
| SI-4 (System Monitoring) | Yes | SI-4 | Three metric filters with alarms (every region, minutes) and three EventBridge rules (home region, seconds) on root activity, console login without MFA, and IAM policy changes, published to the caller's SNS topic |
| AU-9(2) (Store on Separate Systems) | Yes | | **Not met.** Single-account trail. See Scope limits |

AU-6 review (Athena) arrives in PR 3.

## GovCloud / CJIS

- CloudTrail behaves the same in GovCloud. The trail ARN is built from `data.aws_partition`, so it becomes `arn:aws-us-gov:cloudtrail:...` without a branch.
- `kms_key_arn` accepts `arn:aws-us-gov:kms:...` (`[a-z-]*` after `aws`).
- CJIS contexts want FIPS endpoints for reading logs. I annotate this and do not build it: the provider endpoint is the caller's choice, not a resource here.

## Inputs

| Name | Type | Default | Notes |
|---|---|---|---|
| `name_prefix` | string | `"grc-lab4"` | Lowercase, digits, hyphens, 40 characters max. All names derive from it |
| `log_bucket_name` | string | required | Bucket name, not ARN |
| `kms_key_arn` | string | required | Customer-managed key ARN. No alias ARN, no SSE-S3 fallback |
| `critical_event_sns_topic_arn` | string | required | SNS topic ARN. The topic and its policy are the caller's |
| `cloudwatch_log_retention_days` | number | `365` | A CloudWatch Logs retention value of 365 or more |
| `environment` | string | required | `dev`, `staging`, or `prod` |
| `project_tag` | string | required | `project` tag |
| `required_compliance_scope` | string | `"fedramp-high"` | `fedramp-high`, `cjis-v6`, or `nist-800-53-rev-5` |
| `tags` | map(string) | `{}` | Merged under the required tags |

## Outputs

| Name | Notes |
|---|---|
| `trail_arn` | |
| `trail_name` | The name the policies' `aws:SourceArn` must match |
| `cloudwatch_log_group_arn` | No `:*` suffix |
| `cloudwatch_log_group_name` | |
| `compliance_attestation` | Booleans read from resource attributes |

Sample attestation after apply:

```json
{
  "module": "cloudtrail-multi-region",
  "module_version": "1.4.0",
  "framework_targets": ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.1"],
  "controls_satisfied": ["AU-2", "AU-3", "AU-9", "AU-11", "AU-12", "SI-4"],
  "known_gaps": ["AU-9(2)"],
  "environment": "dev",
  "required_compliance_scope": "fedramp-high",
  "logging_enabled": true,
  "multi_region": true,
  "log_file_validation": true,
  "kms_encrypted": true,
  "cloudwatch_retention_365": true,
  "cloudwatch_delivery_configured": true,
  "management_events_all": true,
  "required_tags_present": true,
  "critical_alarms_present": true
}
```

`cloudwatch_delivery_configured` checks that the trail points at this module's group and role. It does not prove delivery. `get-trail-status` and its `LatestCloudWatchLogsDeliveryError` field do that. `critical_alarms_present` checks that the alarms and rules are on and point at the topic. It does not prove delivery.

## Usage

```hcl
module "audit_trail" {
  source = "git::https://github.com/0xBahalaNa/aws-grc-terraform-modules.git//modules/cloudtrail-multi-region?ref=v1.4.0"

  log_bucket_name = "grc-lab2-evidence"
  kms_key_arn     = "arn:aws:kms:us-east-1:111122223333:key/00000000-0000-0000-0000-000000000000"
  environment     = "dev"
  project_tag     = "lab-4-cloudtrail-multi-region"

  critical_event_sns_topic_arn = "arn:aws:sns:us-east-1:111122223333:grc-lab4-critical-events"
}
```

`v1.4.0` is not tagged until PR 3 merges. Until then, point `?ref=` at a commit.

## Requirements

- Terraform >= 1.6
- AWS provider >= 6.0.0: `data.aws_region` exposes `region`
- An existing bucket from `s3-compliant-bucket`, its CMK, and the policy statements above on both
- An existing SNS topic with the `AllowEventBridgePublish` statement above

## Examples

```bash
cd modules/cloudtrail-multi-region/examples/basic && terraform init && terraform validate
```

`validate` needs no AWS credentials. `plan` needs credentials, a region, and the placeholder bucket name and key ARN replaced with real ones.

## License

MIT. See parent repo `LICENSE`.
