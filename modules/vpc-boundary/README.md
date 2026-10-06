# Module: vpc-boundary

Lab 3 module (v1.3.0). CJI enclave boundary aligned with NIST 800-53 Rev 5 **SC-7 / SC-7(3) / SC-7(5)**, **AC-4**, and **AU-2 / AU-3 / AU-12**, with CJIS v6.1 treated as the same enclave (the VPC is the boundary). **AU-9** is the destination bucket's control, not a resource this module creates.

> **Status: v1.3.0 implemented.** One VPC, four subnets across two AZs, one internet gateway, one zonal NAT, two route tables, four chained security groups, a private NACL with SSH deny at rule 50, an S3 Gateway endpoint plus KMS and Secrets Manager Interface endpoints, and VPC Flow Logs (ALL) to an existing bucket. Companion Console walkthrough: [luigicarpio.dev/blog/2026-09-aws-lab-3-vpc-boundary](https://luigicarpio.dev/blog/2026-09-aws-lab-3-vpc-boundary). OPA/Rego policy bundle is **deferred** to the chassis minor: not in this module. Same call as Lab 2.

## What This Module Creates

| Resource | Control |
|---|---|
| `aws_vpc` (DNS support + DNS hostnames on) | SC-7 |
| Four `aws_subnet` resources (public `.1`/`.2`, private `.11`/`.12`) | SC-7, SC-7(3) |
| `aws_internet_gateway` | SC-7(3) |
| `aws_eip` + zonal `aws_nat_gateway` in public-a | SC-7 |
| `rt-public` (`0.0.0.0/0` → IGW) and `rt-private` (`0.0.0.0/0` → NAT) | SC-7(3) |
| `public-alb-443`, `app-from-alb`, `data-from-app`, `vpce-443` | SC-7(5), AC-4 |
| `nacl-private` on both private subnets, SSH deny at rule 50 | AC-4, SC-7 |
| S3 Gateway endpoint on both route tables | SC-7 |
| KMS + Secrets Manager Interface endpoints, private DNS on | SC-7 |
| `aws_flow_log` traffic ALL to S3 | AU-2, AU-3, AU-12 |

**Scope limits (honest framing):**

- **One zonal NAT, in public-a.** The provider can build a regional NAT (`availability_mode = "regional"`). I set `zonal` because that is what the console build proved. HA is a second NAT in public-b. I did not build it. If AZ a is down, private egress is down with it.

- **The flow-log bucket is not created here.** Pass `flow_logs_bucket_arn`. I expect that bucket to come from [`s3-compliant-bucket` v1.2.1](../s3-compliant-bucket/README.md) (SSE-KMS with a customer-managed CMK, Object Lock GOVERNANCE, TLS-only policy). v1.2.1 does not grant `delivery.logs.amazonaws.com`. You add the statements in the next section. I did not ship a v1.2.2 toggle: this module never calls the bucket module, and the lab account already carries the grant on the existing bucket.

- **Names are fixed** (`rt-private`, `data-from-app`, and the rest). The walkthrough's verify commands filter on those names. A second copy of this module in the same account and region will collide.

- **Public subnets set `map_public_ip_on_launch = true`.** That is the NAT's subnet and the probe's subnet. Private subnets set it false. tfsec `aws-ec2-no-public-ip-subnet` and checkov `CKV_AWS_130` flag the public pair. I left the findings in place.

- **The VPC default security group is unused.** I do not strip its rules. Checkov `CKV2_AWS_12` flags that. Public subnets stay on the VPC default NACL. The deny-by-default NACL is the private one. Inbound rule 110 allows TCP 1024-65535 from `0.0.0.0/0` so NAT replies have a way back. That range includes 3389, which is why checkov `CKV_AWS_231` fires. No security group in this module allows 3389.

- **`public-alb-443`, `app-from-alb`, and `data-from-app` are not attached to an ENI here.** This module does not create instances. Checkov `CKV2_AWS_5` flags those three. `vpce-443` is attached to the Interface endpoints.

- **Rule 50 denies SSH from `0.0.0.0/0`, including hosts inside the VPC.** Nobody SSHes the private tier. Session Manager is the admin path, and this module does not build it.

- **Not in this module:** WAF, ALB, Shield, Route 53 Resolver query logging, SSM and CloudWatch Logs endpoints, a second NAT.

NAT is about $0.045/hr plus data. Each Interface endpoint is about $0.01/hr per AZ, and this module creates two services across two AZs. Destroy the stack when you are done. I left a console build up for four days once; the NAT line was the whole bill.

## Flow log delivery grant

`s3-compliant-bucket` v1.2.1's bucket policy is the TLS deny only. Flow Logs will create either way, then fail delivery, unless the bucket and the CMK both allow `delivery.logs.amazonaws.com`.

Keep the existing `DenyInsecureTransport` statement. Add the two bucket statements under it. Do not let the console attach a flow-log policy for you: that write replaces the whole bucket policy and drops the TLS deny.

Bucket policy, two statements. Swap `BUCKET`, `ACCOUNT_ID`, and `REGION`. In GovCloud the ARNs use the `aws-us-gov` partition (`arn:aws-us-gov:s3:::...`, `arn:aws-us-gov:logs:...`).

```json
{
  "Sid": "AWSLogDeliveryWrite",
  "Effect": "Allow",
  "Principal": { "Service": "delivery.logs.amazonaws.com" },
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::BUCKET/AWSLogs/ACCOUNT_ID/*",
  "Condition": {
    "StringEquals": {
      "s3:x-amz-acl": "bucket-owner-full-control",
      "aws:SourceAccount": "ACCOUNT_ID"
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:logs:REGION:ACCOUNT_ID:*"
    }
  }
}
```

```json
{
  "Sid": "AWSLogDeliveryAclCheck",
  "Effect": "Allow",
  "Principal": { "Service": "delivery.logs.amazonaws.com" },
  "Action": "s3:GetBucketAcl",
  "Resource": "arn:aws:s3:::BUCKET",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "ACCOUNT_ID"
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:logs:REGION:ACCOUNT_ID:*"
    }
  }
}
```

CMK key policy, one statement. The bucket's default encryption must name the CMK by key ARN. A key id makes the destination undeliverable.

```json
{
  "Sid": "AllowVPCFlowLogsDelivery",
  "Effect": "Allow",
  "Principal": { "Service": "delivery.logs.amazonaws.com" },
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "ACCOUNT_ID"
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:logs:REGION:ACCOUNT_ID:*"
    }
  }
}
```

The bucket has to be in the same region as the VPC. Object Lock GOVERNANCE on that bucket did not block delivery in the lab; each object inherited the bucket's retention.

## Controls Addressed

NIST states the control. FedRAMP High selects SC-7 and enhancements (3), (4), (5), (7), (8), (10), (12), (18), (20), and (21). The SC-7 enhancements this module maps are (3) and (5). CJIS v6.1 does not add a tighter number on this row: the delta that matters here is that the VPC is the CJI enclave, and the flow-log objects sit on the Lab 2 CMK (agency-managed key, Lab 2's SC-13 / SC-28 row).

| NIST 800-53 Rev 5 | FedRAMP High | CJIS v6.1 | How This Module Enforces It |
|---|:---:|:---:|---|
| SC-7 (Boundary Protection) | Yes | Enclave: the VPC is the boundary | Public and private subnets. Managed interfaces are the IGW, the NAT, and the endpoints |
| SC-7(3) (Access Points) | Yes | Same enhancement, enclave framing | One IGW. Private `0.0.0.0/0` points at the NAT. The private route resource has no `gateway_id` argument, so a caller cannot point it at the IGW |
| SC-7(5) (Deny by Default / Allow by Exception) | Yes | Same enhancement | SG chain: each inbound source is the previous group's ID, except the edge (TCP 443 from `0.0.0.0/0`) and the endpoint ENIs (TCP 443 from the VPC CIDR). `data-from-app` has no egress |
| AC-4 (Information Flow Enforcement) | Yes | AC-4 | NACL rule 50 denies TCP 22 from `0.0.0.0/0` before rule 100 allows the VPC CIDR. Implicit deny covers everything else |
| AU-2 / AU-3 / AU-12 (Event Logging / Content / Generation) | Yes | AU-2, AU-3 | Flow log on the VPC, `traffic_type = ALL`, 10-minute aggregation, default format. No off switch |
| AU-9 (Protection of Audit Information) | Yes | AU-9, via the Lab 2 bucket | Inherited. Objects are SSE-KMS with the bucket CMK and the bucket's Object Lock retention. This module only passes the bucket ARN |
| CM-6 (Configuration Settings) | Yes | CM-6 | Required tags via `merge(var.tags, local.required_tags)`. DNS flags, NACL rule 50, and flow-log traffic type are literals |

The private-route guardrail is structural. A `validation` block would be the wrong tool: there is no variable that names a gateway for `rt-private`. The resource's arguments are the route table, `0.0.0.0/0`, and the NAT id.

## GovCloud / CJIS

- Endpoint service names change with the region. This module builds `com.amazonaws.<region>.s3` (and `.kms`, `.secretsmanager`) from the provider region. In `us-gov-west-1` that is `com.amazonaws.us-gov-west-1.kms`. I do not hardcode `us-east-1`.
- Private DNS suffix in GovCloud is `amazonaws.us-gov`, not `amazonaws.com`. Private DNS is still the `private_dns_enabled = true` flag. A commercial `nslookup kms.us-east-1.amazonaws.com` is the wrong test there.
- `flow_logs_bucket_arn` accepts `arn:aws-us-gov:s3:::...` (`[a-z-]*` after `aws`). The delivery statements in GovCloud use the `aws-us-gov` partition on both the bucket ARN and the `aws:SourceArn`.
- Commercial partitions have a separate Interface service for `kms-fips`. GovCloud's standard endpoints are FIPS. I annotated that. I did not add a second endpoint.
- Shield Advanced is not in every GovCloud partition. That only matters for the shed WAF layer, which this module does not build.
- Anything that terminates CJI outside this VPC (a laptop, a SaaS) needs its own SC-7 story. This module is the enclave, not that path.

## Requirements

- Terraform >= 1.9: `az_b`'s validation reads `az_a`. See [cross-object validation](https://developer.hashicorp.com/terraform/language/block/variable#cross-object-validation-conditions).
- AWS provider >= 6.24.0: `availability_mode` on `aws_nat_gateway`. See [aws_nat_gateway](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/nat_gateway).
- An existing bucket from `s3-compliant-bucket` v1.2.1, plus the delivery statements above on that bucket and its CMK.
- Two different AZ names in the provider region. The module does not look them up.

## Compliance Attestation Output

Self-verifying booleans read **deployed resource attributes** (not inputs). Sample as `examples/basic` would produce it after apply:

```json
{
  "module": "vpc-boundary",
  "module_version": "1.3.0",
  "framework_targets": ["NIST 800-53 Rev 5", "FedRAMP High", "CJIS v6.1"],
  "controls_satisfied": ["SC-7", "SC-7(3)", "SC-7(5)", "AC-4", "AU-2", "AU-3", "AU-12"],
  "environment": "dev",
  "required_compliance_scope": "fedramp-high",
  "private_has_no_igw_route": true,
  "flow_logs_all_traffic": true,
  "flow_logs_to_s3": true,
  "s3_gateway_endpoint_present": true,
  "kms_interface_endpoint_present": true,
  "required_tags_present": true
}
```

`private_has_no_igw_route` reads the module's `0.0.0.0/0` route on `rt-private`. It does not inventory routes someone adds later outside this state. `flow_logs_to_s3` checks the flow log's destination type and ARN shape. It does not open the bucket policy.

## Usage

```hcl
module "enclave" {
  source = "git::https://github.com/0xBahalaNa/aws-grc-terraform-modules.git//modules/vpc-boundary?ref=v1.3.0"

  cidr_block           = "10.50.0.0/16"
  az_a                 = "us-east-1a"
  az_b                 = "us-east-1b"
  flow_logs_bucket_arn = "arn:aws:s3:::grc-lab2-evidence"
  environment          = "dev"
  project_tag          = "lab-3-vpc-boundary"
}
```

Pin `?ref=` to a tagged release. `az_a` and `az_b` have no defaults. `flow_logs_bucket_arn` has no default and rejects null. Passing the same AZ twice fails the plan. Omitting the bucket ARN fails the plan.

## Examples

Runnable caller under `examples/basic/`. From the repo root:

```bash
cd modules/vpc-boundary/examples/basic && terraform init && terraform validate
```

`validate` needs no AWS credentials. `terraform plan` needs credentials, a region (`AWS_REGION` or `~/.aws/config`), two AZ names in that region, and the placeholder bucket ARN replaced with a real bucket that already grants delivery. Plan creates a NAT. Destroy the same sitting.

## Roadmap

- **v1.3.0 (this):** Lab 3 core (VPC, subnets, IGW, one NAT, route tables, four SGs, private NACL, three endpoints, flow logs, attestation)
- **Chassis minor:** OPA/Rego policy bundle + CI gates
- **Not scheduled here:** WAF, ALB, Shield, Resolver query logging, SSM/Logs endpoints, HA NAT

## License

MIT. See parent repo `LICENSE`.
