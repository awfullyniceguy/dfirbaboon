variable "project_prefix" {
  type        = string
  description = "Project resource naming prefix"
}

variable "intake_bucket_name" {
  type        = string
  description = "Name of the intake S3 bucket"
}

variable "large_image_threshold_gib" {
  type        = number
  description = "Size routing boundary in GiB (e.g. 50)"
  default     = 50
}

variable "ecs_cluster_arn" {
  type        = string
  description = "ARN of the ECS cluster"
}

variable "ecs_task_definition_arn" {
  type        = string
  description = "ARN of the ECS Fargate task definition"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for ECS task networking"
}

variable "security_group_id" {
  type        = string
  description = "Security group ID for workers"
}

variable "eventbridge_invoke_role_arn" {
  type        = string
  description = "ARN of the EventBridge invocation IAM role"
}

variable "batch_job_queue_arn" {
  type        = string
  description = "ARN of the AWS Batch job queue"
}

variable "batch_job_definition_arn" {
  type        = string
  description = "ARN of the AWS Batch job definition"
}

variable "enable_event_rules" {
  type        = bool
  description = "Whether to create EventBridge automated intake event rules"
  default     = true
}

locals {
  threshold_bytes = var.large_image_threshold_gib * 1024 * 1024 * 1024
}

# -----------------------------------------------------------------------------
# 1. Evidence Drop <= 50 GiB -> ECS Fargate
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "evidence_drop" {
  count       = var.enable_event_rules ? 1 : 0
  name        = "${var.project_prefix}-evidence-drop"
  description = "Dispatches evidence objects <= ${var.large_image_threshold_gib} GiB to serverless ECS Fargate"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = {
        name = [var.intake_bucket_name]
      }
      object = {
        size = [
          {
            numeric = ["<=", local.threshold_bytes]
          }
        ]
      }
    }
  })

  tags = {
    Name = "${var.project_prefix}-evidence-drop-rule"
  }
}

resource "aws_cloudwatch_event_target" "ecs_worker" {
  count    = var.enable_event_rules ? 1 : 0
  rule     = aws_cloudwatch_event_rule.evidence_drop[0].name
  arn      = var.ecs_cluster_arn
  role_arn = var.eventbridge_invoke_role_arn

  ecs_target {
    task_count          = 1
    task_definition_arn = var.ecs_task_definition_arn
    launch_type         = "FARGATE"
    platform_version    = "LATEST"

    network_configuration {
      subnets          = var.subnet_ids
      security_groups  = [var.security_group_id]
      assign_public_ip = true
    }
  }

  input_transformer {
    input_paths = {
      source_bucket = "$.detail.bucket.name"
      source_key    = "$.detail.object.key"
      source_etag   = "$.detail.object.etag"
    }

    input_template = <<-JSON
      {
        "containerOverrides": [
          {
            "name": "${var.project_prefix}-worker",
            "environment": [
              { "name": "SOURCE_BUCKET", "value": <source_bucket> },
              { "name": "SOURCE_KEY", "value": <source_key> },
              { "name": "SOURCE_ETAG", "value": <source_etag> }
            ]
          }
        ]
      }
    JSON
  }
}

# -----------------------------------------------------------------------------
# 2. Evidence Drop > 50 GiB -> AWS Batch (EC2 i4i.2xlarge NVMe)
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "evidence_drop_large" {
  count       = var.enable_event_rules ? 1 : 0
  name        = "${var.project_prefix}-evidence-drop-large"
  description = "Routes evidence objects > ${var.large_image_threshold_gib} GiB to AWS Batch on EC2 with local NVMe"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = {
        name = [var.intake_bucket_name]
      }
      object = {
        size = [
          {
            numeric = [">", local.threshold_bytes]
          }
        ]
      }
    }
  })

  tags = {
    Name = "${var.project_prefix}-evidence-drop-large-rule"
  }
}

resource "aws_cloudwatch_event_target" "batch_worker" {
  count    = var.enable_event_rules ? 1 : 0
  rule     = aws_cloudwatch_event_rule.evidence_drop_large[0].name
  arn      = var.batch_job_queue_arn
  role_arn = var.eventbridge_invoke_role_arn

  batch_target {
    job_definition = var.batch_job_definition_arn
    job_name       = "${var.project_prefix}-large-analysis"
    job_attempts   = 1
  }

  input_transformer {
    input_paths = {
      source_bucket = "$.detail.bucket.name"
      source_key    = "$.detail.object.key"
      source_etag   = "$.detail.object.etag"
    }

    input_template = <<-JSON
      {
        "containerOverrides": {
          "environment": [
            { "name": "SOURCE_BUCKET", "value": <source_bucket> },
            { "name": "SOURCE_KEY", "value": <source_key> },
            { "name": "SOURCE_ETAG", "value": <source_etag> }
          ]
        }
      }
    JSON
  }
}

output "fargate_rule_arn" {
  value = var.enable_event_rules ? aws_cloudwatch_event_rule.evidence_drop[0].arn : null
}

output "batch_rule_arn" {
  value = var.enable_event_rules ? aws_cloudwatch_event_rule.evidence_drop_large[0].arn : null
}
