variable "project_prefix" {
  type        = string
  description = "Project resource naming prefix"
}

variable "vpc_id" {
  type        = string
  description = "Optional custom VPC ID. Defaults to the AWS default VPC if null."
  default     = null
}

variable "subnet_ids" {
  type        = list(string)
  description = "Optional custom Subnet IDs. Defaults to default VPC subnets if empty."
  default     = []
}

variable "create_s3_vpc_endpoint" {
  type        = bool
  description = "Whether to create S3 Gateway VPC endpoint. Set to false if VPC already contains an S3 gateway endpoint."
  default     = true
}

variable "create_security_group" {
  type        = bool
  description = "Whether to create the worker egress security group"
  default     = true
}

variable "existing_security_group_id" {
  type        = string
  description = "Optional pre-existing security group ID if create_security_group is false"
  default     = null
}

data "aws_region" "current" {}

data "aws_vpc" "default" {
  count   = var.vpc_id == null ? 1 : 0
  default = true
}

locals {
  vpc_id = var.vpc_id != null ? var.vpc_id : data.aws_vpc.default[0].id
}

data "aws_subnets" "selected" {
  count = length(var.subnet_ids) == 0 ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }
}

locals {
  subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.selected[0].ids
}

data "aws_route_tables" "selected" {
  vpc_id = local.vpc_id
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.create_s3_vpc_endpoint ? 1 : 0
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.selected.ids

  tags = {
    Name = "${var.project_prefix}-s3-gateway-endpoint"
  }
}

resource "aws_security_group" "worker" {
  count       = var.create_security_group ? 1 : 0
  name        = "${var.project_prefix}-worker-sg"
  description = "Egress-only security group for dfirbaboon forensic workers"
  vpc_id      = local.vpc_id

  egress {
    description      = "Allow all outbound traffic for S3, ECR, and CloudWatch Logs"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.project_prefix}-worker-sg"
  }
}

output "vpc_id" {
  value = local.vpc_id
}

output "subnet_ids" {
  value = local.subnet_ids
}

output "security_group_id" {
  value = var.create_security_group ? aws_security_group.worker[0].id : var.existing_security_group_id
}

output "s3_vpc_endpoint_id" {
  value = var.create_s3_vpc_endpoint ? aws_vpc_endpoint.s3[0].id : null
}
