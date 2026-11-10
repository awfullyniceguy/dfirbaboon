variable "project_prefix" {
  type        = string
  description = "Project resource naming prefix"
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of the KMS CMK"
}

variable "worker_image_tag" {
  type        = string
  description = "Worker container image tag"
  default     = "latest"
}

variable "fargate_cpu" {
  type        = number
  description = "Fargate task vCPU units (e.g. 4096 = 4 vCPU)"
  default     = 4096
}

variable "fargate_memory" {
  type        = number
  description = "Fargate task memory in MiB (e.g. 8192 = 8 GiB)"
  default     = 8192
}

variable "ephemeral_storage_gib" {
  type        = number
  description = "Fargate ephemeral storage in GiB (21 to 200)"
  default     = 100
}

variable "batch_instance_types" {
  type        = list(string)
  description = "EC2 instance types for large Batch jobs (local NVMe SSD)"
  default     = ["i4i.2xlarge", "i3en.2xlarge", "m6i.2xlarge"]
}

variable "batch_vcpus" {
  type        = number
  description = "vCPUs assigned to large Batch job container"
  default     = 8
}

variable "batch_memory_mib" {
  type        = number
  description = "Memory in MiB assigned to large Batch job container"
  default     = 60000
}

variable "batch_scratch_gib" {
  type        = number
  description = "Root gp3 volume size in GiB for Batch instances as fallback scratch"
  default     = 1024
}

variable "batch_job_timeout_hours" {
  type        = number
  description = "Batch job timeout in hours"
  default     = 48
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for compute execution"
}

variable "security_group_id" {
  type        = string
  description = "Security group ID for workers"
}

variable "ecs_task_execution_role_arn" {
  type        = string
  description = "ARN of the ECS execution role"
}

variable "ecs_task_role_arn" {
  type        = string
  description = "ARN of the ECS task role"
}

variable "batch_instance_profile_arn" {
  type        = string
  description = "ARN of the Batch instance profile"
}

variable "cloudwatch_log_group_name" {
  type        = string
  description = "Name of the worker CloudWatch log group"
}

variable "create_ecr_repository" {
  type        = bool
  description = "Whether to create ECR repository for worker container"
  default     = true
}

variable "existing_ecr_repository_url" {
  type        = string
  description = "URL of pre-existing ECR repository if create_ecr_repository is false"
  default     = null
}

variable "create_vault_bucket" {
  type        = bool
  description = "Whether worker creates the incident vault bucket at runtime"
  default     = true
}

variable "vault_bucket_name" {
  type        = string
  description = "Optional pre-provisioned vault bucket name"
  default     = null
}

variable "vault_prefix" {
  type        = string
  description = "Optional vault key prefix"
  default     = null
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  ecr_repository_url = var.create_ecr_repository ? aws_ecr_repository.worker[0].repository_url : var.existing_ecr_repository_url
  worker_image_uri   = "${local.ecr_repository_url}:${var.worker_image_tag}"

  base_env = [
    { name = "AWS_ACCOUNT_ID", value = local.account_id },
    { name = "AWS_DEFAULT_REGION", value = data.aws_region.current.region },
    { name = "KMS_KEY_ARN", value = var.kms_key_arn },
    { name = "PROJECT_PREFIX", value = var.project_prefix },
    { name = "CREATE_VAULT_BUCKET", value = tostring(var.create_vault_bucket) }
  ]

  vault_bucket_env = var.vault_bucket_name != null ? [{ name = "VAULT_BUCKET", value = var.vault_bucket_name }] : []
  vault_prefix_env = var.vault_prefix != null ? [{ name = "VAULT_PREFIX", value = var.vault_prefix }] : []

  container_env = concat(local.base_env, local.vault_bucket_env, local.vault_prefix_env)
}

# -----------------------------------------------------------------------------
# 1. ECR Container Repository
# -----------------------------------------------------------------------------

resource "aws_ecr_repository" "worker" {
  count                = var.create_ecr_repository ? 1 : 0
  name                 = "${var.project_prefix}-worker"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = {
    Name = "${var.project_prefix}-worker"
  }
}

resource "aws_ecr_lifecycle_policy" "worker" {
  count      = var.create_ecr_repository ? 1 : 0
  repository = aws_ecr_repository.worker[0].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Retain last 5 tagged images for rollback"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# 2. ECS Fargate Cluster & Task Definition
# -----------------------------------------------------------------------------

resource "aws_ecs_cluster" "main" {
  name = "${var.project_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${var.project_prefix}-cluster"
  }
}

resource "aws_ecs_task_definition" "worker" {
  family                   = "${var.project_prefix}-tsk-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.fargate_cpu)
  memory                   = tostring(var.fargate_memory)
  execution_role_arn       = var.ecs_task_execution_role_arn
  task_role_arn            = var.ecs_task_role_arn

  ephemeral_storage {
    size_in_gib = var.ephemeral_storage_gib
  }

  container_definitions = jsonencode([
    {
      name      = "${var.project_prefix}-worker"
      image     = local.worker_image_uri
      essential = true

      environment = local.container_env

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = var.cloudwatch_log_group_name
          awslogs-region        = data.aws_region.current.region
          awslogs-stream-prefix = "forensic-worker"
        }
      }
    }
  ])

  tags = {
    Name = "${var.project_prefix}-tsk-worker"
  }
}

# -----------------------------------------------------------------------------
# 3. AWS Batch on EC2 (Large Server Disk Images)
# -----------------------------------------------------------------------------

locals {
  batch_userdata = <<-EOF
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="==MYBOUNDARY=="

    --==MYBOUNDARY==
    Content-Type: text/x-shellscript; charset="us-ascii"
    #!/bin/bash
    set -euxo pipefail

    NVME_DEV=$(lsblk -d -n -o NAME,MODEL 2>/dev/null | grep -i 'Instance Storage' | awk '{print "/dev/" $1}' | head -n 1 || true)
    if [ -z "$${NVME_DEV}" ]; then
      NVME_DEV=$(lsblk -d -n -o NAME,TYPE 2>/dev/null | grep 'disk' | grep -v 'xvda' | grep -v 'nvme0n1' | head -n 1 | awk '{print "/dev/" $1}' || true)
    fi

    if [ -n "$${NVME_DEV}" ] && [ -b "$${NVME_DEV}" ]; then
      echo "Formatting local NVMe SSD $${NVME_DEV} with XFS for high-speed forensic scratch..."
      mkfs.xfs -f "$${NVME_DEV}"
      mkdir -p /work
      mount -o noatime,nodiratime,logbufs=8,logbsize=256k "$${NVME_DEV}" /work
      chmod 1777 /work
    else
      echo "No local NVMe SSD detected; falling back to root volume scratch at /work."
      mkdir -p /work
      chmod 1777 /work
    fi
    --==MYBOUNDARY==--
  EOF
}

resource "aws_launch_template" "batch_scratch" {
  name_prefix   = "${var.project_prefix}-batch-lt-"
  image_id      = ""
  instance_type = var.batch_instance_types[0]

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.batch_scratch_gib
      volume_type           = "gp3"
      iops                  = 6000
      throughput            = 500
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      delete_on_termination = true
    }
  }

  user_data = base64encode(local.batch_userdata)

  tags = {
    Name = "${var.project_prefix}-batch-launch-template"
  }
}

resource "aws_batch_compute_environment" "large" {
  name  = "${var.project_prefix}-large-compute-env"
  type  = "MANAGED"
  state = "ENABLED"

  compute_resources {
    type                = "EC2"
    allocation_strategy = "BEST_FIT_PROGRESSIVE"
    min_vcpus           = 0
    max_vcpus           = 64
    desired_vcpus       = 0
    instance_type       = var.batch_instance_types
    subnets             = var.subnet_ids
    security_group_ids  = [var.security_group_id]
    instance_role       = var.batch_instance_profile_arn

    launch_template {
      launch_template_id = aws_launch_template.batch_scratch.id
      version            = "$Latest"
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.project_prefix}-large-compute-env"
  }
}

resource "aws_batch_job_queue" "large" {
  name     = "${var.project_prefix}-large-queue"
  state    = "ENABLED"
  priority = 1

  compute_environment_order {
    order               = 1
    compute_environment = aws_batch_compute_environment.large.arn
  }

  tags = {
    Name = "${var.project_prefix}-large-queue"
  }
}

resource "aws_batch_job_definition" "large" {
  name = "${var.project_prefix}-tsk-worker-large"
  type = "container"

  timeout {
    attempt_duration_seconds = var.batch_job_timeout_hours * 3600
  }

  container_properties = jsonencode({
    image            = local.worker_image_uri
    jobRoleArn       = var.ecs_task_role_arn
    executionRoleArn = var.ecs_task_execution_role_arn
    resourceRequirements = [
      { type = "VCPU", value = tostring(var.batch_vcpus) },
      { type = "MEMORY", value = tostring(var.batch_memory_mib) }
    ]
    environment = local.container_env
    volumes = [
      { name = "work", host = { sourcePath = "/work" } }
    ]
    mountPoints = [
      { sourceVolume = "work", containerPath = "/tmp/work", readOnly = false }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = var.cloudwatch_log_group_name
        awslogs-region        = data.aws_region.current.region
        awslogs-stream-prefix = "batch-worker"
      }
    }
  })

  tags = {
    Name = "${var.project_prefix}-tsk-worker-large"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "ecr_repository_url" {
  value = local.ecr_repository_url
}

output "ecs_cluster_arn" {
  value = aws_ecs_cluster.main.arn
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "ecs_task_definition_arn" {
  value = aws_ecs_task_definition.worker.arn
}

output "batch_job_queue_arn" {
  value = aws_batch_job_queue.large.arn
}

output "batch_job_definition_arn" {
  value = aws_batch_job_definition.large.arn
}
