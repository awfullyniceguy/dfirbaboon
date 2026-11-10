variable "project_prefix" {
  type        = string
  description = "Project resource naming prefix"
}

variable "kms_key_arn" {
  type        = string
  description = "ARN of the KMS CMK"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention in days"
  default     = 90
}

variable "audit_trail_bucket_id" {
  type        = string
  description = "S3 bucket ID for CloudTrail audit log storage"
  default     = ""
}

variable "intake_bucket_arn" {
  type        = string
  description = "ARN of the intake S3 bucket"
}

variable "vault_bucket_arn" {
  type        = string
  description = "Optional ARN of pre-provisioned vault bucket"
  default     = null
}

variable "ecs_cluster_name" {
  type        = string
  description = "Name of the ECS cluster"
}

variable "batch_job_queue_arn" {
  type        = string
  description = "ARN of the Batch job queue"
}

variable "create_cloudtrail" {
  type        = bool
  description = "Whether to create a CloudTrail trail for forensic audit events. Set to false if enterprise organizational trail is active."
  default     = true
}

variable "create_log_group" {
  type        = bool
  description = "Whether to create CloudWatch log group. Set to false if using existing log group."
  default     = true
}

variable "existing_log_group_name" {
  type        = string
  description = "Name of pre-existing CloudWatch log group if create_log_group is false"
  default     = null
}

locals {
  log_group_name = var.create_log_group ? aws_cloudwatch_log_group.worker[0].name : var.existing_log_group_name

  s3_trail_prefix_arns = compact([
    "${var.intake_bucket_arn}/",
    "arn:aws:s3:::${var.project_prefix}-inc",
    var.vault_bucket_arn != null ? "${var.vault_bucket_arn}/" : null
  ])
}

# -----------------------------------------------------------------------------
# 1. CloudWatch Log Group (KMS Encrypted)
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "worker" {
  count             = var.create_log_group ? 1 : 0
  name              = "/ecs/${var.project_prefix}-tsk-worker"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = {
    Name = "${var.project_prefix}-worker-logs"
  }
}

# -----------------------------------------------------------------------------
# 2. AWS CloudTrail Forensic Audit Trail (S3 Data Events & KMS)
# -----------------------------------------------------------------------------

resource "aws_cloudtrail" "forensic_trail" {
  count                         = var.create_cloudtrail ? 1 : 0
  name                          = "${var.project_prefix}-forensic-audit-trail"
  s3_bucket_name                = var.audit_trail_bucket_id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn

  advanced_event_selector {
    name = "Log all management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "Log S3 data events for intake and incident vaults"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = local.s3_trail_prefix_arns
    }
  }

  tags = {
    Name = "${var.project_prefix}-forensic-audit-trail"
  }
}

# -----------------------------------------------------------------------------
# 3. CloudWatch Metric Filter & Alarms
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "worker_errors" {
  count          = var.create_log_group ? 1 : 0
  name           = "${var.project_prefix}-worker-error-filter"
  pattern        = "[timestamp, level = *ERROR* || level = *CRITICAL* || level = *Traceback*, ...]"
  log_group_name = local.log_group_name

  metric_transformation {
    name      = "${var.project_prefix}-worker-errors"
    namespace = "DFIRBaboon"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "worker_errors" {
  count               = var.create_log_group ? 1 : 0
  alarm_name          = "${var.project_prefix}-worker-error-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.worker_errors[0].metric_transformation[0].name
  namespace           = "DFIRBaboon"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Triggered when dfirbaboon worker logs an ERROR, CRITICAL or uncaught traceback"

  tags = {
    Name = "${var.project_prefix}-worker-error-alarm"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "log_group_name" {
  value = local.log_group_name
}

output "log_group_arn" {
  value = var.create_log_group ? aws_cloudwatch_log_group.worker[0].arn : null
}

output "cloudtrail_arn" {
  value = var.create_cloudtrail ? aws_cloudtrail.forensic_trail[0].arn : null
}

output "worker_error_alarm_arn" {
  value = var.create_log_group ? aws_cloudwatch_metric_alarm.worker_errors[0].arn : null
}
