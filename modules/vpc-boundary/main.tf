# vpc-boundary — Lab 3 module (v1.3.0)
#
# Codifies the Lab 3 console baseline: one VPC, four subnets across two AZs,
# one IGW, one zonal NAT, two route tables, four chained security groups,
# a private NACL with SSH deny at rule 50, S3 Gateway + KMS and Secrets
# Manager Interface endpoints, and VPC Flow Logs (ALL) to an existing bucket.
# Companion walkthrough: luigicarpio.dev/blog/2026-09-aws-lab-3-vpc-boundary
#
# Not built (shed): WAF, ALB, Shield, Resolver query logging, SSM/Logs
# endpoints, a second NAT.

# data "aws_region" reads the provider's region. The module never types a
# region string. In AWS provider 6 the attribute is region (name is retired).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region
data "aws_region" "current" {}

# locals is a computed-values block — not an input, not a resource.
# required_tags is a map so merge() can overwrite by key (Lab 2.4 pattern #1 / CM-6).
# https://developer.hashicorp.com/terraform/language/functions/merge
#
# cidrsubnet(prefix, newbits, netnum) carves a smaller network out of a larger
# one. newbits 8 turns a /16 into a /24. netnum picks which block: 1, 2, 11, 12
# are the lab's third octets. Literals would ignore a caller who passed a
# different /16 and create subnets outside the VPC.
# https://developer.hashicorp.com/terraform/language/functions/cidrsubnet
locals {
  required_tags = {
    compliance_scope = var.required_compliance_scope
    project          = var.project_tag
    environment      = var.environment
    managed_by       = "aws-grc-terraform-modules/vpc-boundary"
    framework_target = "FedRAMP-High,CJIS-v6.1,NIST-800-53-Rev-5"
    module_version   = "1.3.0"
  }

  public_a_cidr  = cidrsubnet(var.cidr_block, 8, 1)
  public_b_cidr  = cidrsubnet(var.cidr_block, 8, 2)
  private_a_cidr = cidrsubnet(var.cidr_block, 8, 11)
  private_b_cidr = cidrsubnet(var.cidr_block, 8, 12)

  # Endpoint service names follow the provider region, so GovCloud
  # (us-gov-west-1) becomes com.amazonaws.us-gov-west-1.kms without a branch.
  s3_endpoint_service             = "com.amazonaws.${data.aws_region.current.region}.s3"
  kms_endpoint_service            = "com.amazonaws.${data.aws_region.current.region}.kms"
  secretsmanager_endpoint_service = "com.amazonaws.${data.aws_region.current.region}.secretsmanager"
}

# SC-7 — the VPC is the enclave. DNS hostnames and DNS resolution are both
# on because Interface endpoint private DNS fails without them. Tenancy stays
# default. There is no variable that turns DNS off.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc
resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, local.required_tags, { Name = "grc-lab3-enclave" })
}

# Four subnet resources, written out. No count and no for_each: two AZs is
# both the floor and the lab. map_public_ip_on_launch is a literal, not a
# variable — public subnets hand out public IPs, private subnets do not.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_a_cidr
  availability_zone       = var.az_a
  map_public_ip_on_launch = true

  tags = merge(var.tags, local.required_tags, { Name = "public-a" })
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_b_cidr
  availability_zone       = var.az_b
  map_public_ip_on_launch = true

  tags = merge(var.tags, local.required_tags, { Name = "public-b" })
}

resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.private_a_cidr
  availability_zone       = var.az_a
  map_public_ip_on_launch = false

  tags = merge(var.tags, local.required_tags, { Name = "private-a" })
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.private_b_cidr
  availability_zone       = var.az_b
  map_public_ip_on_launch = false

  tags = merge(var.tags, local.required_tags, { Name = "private-b" })
}

# SC-7(3) — one internet gateway, attached by setting vpc_id.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/internet_gateway
resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, local.required_tags, { Name = "grc-lab3-igw" })
}

# The NAT's public address. domain = "vpc" is the current argument
# (vpc = true is the deprecated form).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = merge(var.tags, local.required_tags, { Name = "grc-lab3-nat-eip" })
}

# One zonal NAT in public-a. availability_mode = "zonal" is explicit because
# the console also offers regional, and the provider default could change.
# depends_on the IGW: the NAT's arguments reference the EIP and the subnet,
# not the gateway, so Terraform's graph would not otherwise wait for it.
# Lab 2.4 pattern #4.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/nat_gateway
resource "aws_nat_gateway" "this" {
  allocation_id     = aws_eip.nat.id
  subnet_id         = aws_subnet.public_a.id
  availability_mode = "zonal"
  connectivity_type = "public"

  tags = merge(var.tags, local.required_tags, { Name = "grc-lab3-nat" })

  depends_on = [aws_internet_gateway.this]
}

# Route tables have no inline route blocks. Inline routes cannot be combined
# with aws_route. The 0.0.0.0/0 routes are separate aws_route resources below.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, local.required_tags, { Name = "rt-public" })
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, local.required_tags, { Name = "rt-private" })
}

# Public default route names the IGW. Private default route names the NAT
# and has no gateway_id argument. That is the "no IGW on private" guardrail:
# structural, not a validation block. The VPC main table is left alone;
# the associations below pull our four subnets off it.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route
resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route" "private_default" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this.id
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

# Four security groups. Descriptions are immutable after create; they match
# the 09-27 console text. Rules are NOT inline. An inline egress on the edge
# group that points at the app group, plus an inline ingress on the app group
# that points back, is a cycle: each group would depend on the other.
# aws_vpc_security_group_*_rule resources depend on the group IDs, and the
# groups themselves do not depend on each other.
# The provider removes the default allow-all egress when no egress block is
# set, which is what "remove the default egress" meant in the console.
# The VPC default security group is left untouched and unused.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group
resource "aws_security_group" "vpce" {
  name        = "vpce-443"
  description = "Interface endpoint ENIs - HTTPS 443 from VPC CIDR only"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, local.required_tags, { Name = "vpce-443" })
}

resource "aws_security_group" "edge" {
  name        = "public-alb-443"
  description = "Edge tier - HTTPS 443 from internet, forwards 8080 to app tier only"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, local.required_tags, { Name = "public-alb-443" })
}

resource "aws_security_group" "app" {
  name        = "app-from-alb"
  description = "App tier - 8080 from edge SG only, egress to data SG and VPC endpoints"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, local.required_tags, { Name = "app-from-alb" })
}

resource "aws_security_group" "data" {
  name        = "data-from-app"
  description = "Data tier - 5432 from app SG only, no egress. SC-7(5) enclave boundary"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, local.required_tags, { Name = "data-from-app" })
}

# Each rule carries a description. referenced_security_group_id is how the
# chain names the previous group. cidr_ipv4 is only used where the lab used
# a CIDR (edge from the internet, endpoints from the VPC).
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule
resource "aws_vpc_security_group_ingress_rule" "edge_https" {
  security_group_id = aws_security_group.edge.id
  description       = "HTTPS from internet to edge"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "edge_to_app" {
  security_group_id            = aws_security_group.edge.id
  description                  = "edge to app tier"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_ingress_rule" "app_from_edge" {
  security_group_id            = aws_security_group.app.id
  description                  = "app from edge only"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.edge.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_data" {
  security_group_id            = aws_security_group.app.id
  description                  = "app to data"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.data.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_vpce" {
  security_group_id            = aws_security_group.app.id
  description                  = "app to Interface endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.vpce.id
}

# prefix_list_id comes off the S3 Gateway endpoint so the rule allows the
# same list the route table uses. pl-63a5400a is us-east-1 only; hardcoding
# it would break every other region, including GovCloud.
resource "aws_vpc_security_group_egress_rule" "app_to_s3" {
  security_group_id = aws_security_group.app.id
  description       = "app to S3 Gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
}

resource "aws_vpc_security_group_ingress_rule" "data_from_app" {
  security_group_id            = aws_security_group.data.id
  description                  = "data from app only"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_ingress_rule" "vpce_https" {
  security_group_id = aws_security_group.vpce.id
  description       = "endpoint ENIs accept HTTPS from the VPC"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.cidr_block
}

# data-from-app and vpce-443 have no egress rule resources. That is the
# "no egress" from the console, not an omitted block Terraform will fill in.

# SC-7 / AC-4 — custom NACL on both private subnets only. Public subnets
# stay on the VPC default NACL. NACLs are stateless: the lowest matching
# rule number wins, then evaluation stops. The API has no description field
# on an entry, so the intent lives in the comment above each block.
# Rule 50 is a literal. It matches SSH from anywhere, including the VPC
# CIDR, before rule 100 can allow it.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/network_acl
resource "aws_network_acl" "private" {
  vpc_id = aws_vpc.this.id
  subnet_ids = [
    aws_subnet.private_a.id,
    aws_subnet.private_b.id,
  ]

  # Inbound 50: explicit SSH deny. The negative test hits this rule.
  ingress {
    rule_no    = 50
    protocol   = "tcp"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }

  # Inbound 100: intra-VPC (app to data, endpoint ENIs).
  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Inbound 110: ephemeral return for NAT egress. Stateless, so the reply
  # needs its own rule. The security group still decides who may connect.
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Outbound 100: intra-VPC.
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Outbound 110: HTTPS via NAT and to the Gateway endpoint prefix.
  egress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  tags = merge(var.tags, local.required_tags, { Name = "nacl-private" })
}

# SC-7 — the S3 Gateway endpoint, and the KMS and Secrets Manager Interface
# endpoints below, are private paths to those AWS APIs. S3 is a route, not
# an ENI. Both route tables so a probe in the public subnet uses it too.
# private_dns_enabled is not set; Gateway endpoints do not change DNS.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = local.s3_endpoint_service
  vpc_endpoint_type = "Gateway"
  route_table_ids = [
    aws_route_table.public.id,
    aws_route_table.private.id,
  ]

  tags = merge(var.tags, local.required_tags, { Name = "s3-gateway" })
}

# KMS and Secrets Manager are written as two resources. Two is two blocks;
# a for_each over a list would be the third repetition, which this lab is not.
# Private DNS is a literal true. Subnets are the two private ones. SG is vpce-443.
resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.this.id
  service_name        = local.kms_endpoint_service
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    aws_subnet.private_a.id,
    aws_subnet.private_b.id,
  ]
  security_group_ids = [aws_security_group.vpce.id]

  tags = merge(var.tags, local.required_tags, { Name = "kms-interface" })
}

resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.this.id
  service_name        = local.secretsmanager_endpoint_service
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids = [
    aws_subnet.private_a.id,
    aws_subnet.private_b.id,
  ]
  security_group_ids = [aws_security_group.vpce.id]

  tags = merge(var.tags, local.required_tags, { Name = "secretsmanager-interface" })
}

# AU-2 / AU-3 / AU-12 — flow logs on the VPC, traffic ALL, destination S3.
# No IAM role: S3 delivery uses the bucket policy, not a role. 600 seconds
# is the console's 10-minute aggregation. Hive-style prefixes stay off.
# The bucket's own SSE-KMS is what encrypts the objects (AU-9); this resource
# does not take a key id when the destination is S3.
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/flow_log
resource "aws_flow_log" "this" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = var.flow_logs_bucket_arn
  max_aggregation_interval = 600

  destination_options {
    file_format                = "plain-text"
    hive_compatible_partitions = false
    per_hour_partition         = false
  }

  tags = merge(var.tags, local.required_tags, { Name = "vpc-flow-logs" })
}
