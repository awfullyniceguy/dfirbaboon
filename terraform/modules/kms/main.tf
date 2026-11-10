variable "project_prefix" {
  type        = string
  description = "Project resource naming prefix"
}

variable "create_kms_key" {
  type        = bool
  description = "Whether to create a new KMS CMK. Set to false to use existing_kms_key_arn."
  default     = true
}

variable "existing_kms_key_arn" {
  type        = string
  description = "ARN of pre-existing KMS CMK if create_kms_key is false"
  default     = null
}

variable "deletion_window_in_days" {
  type        = number
  description = "Duration in days before KMS key is permanently deleted"
  default     = 30
}

variable "rotation_period_in_days" {
  type        = number
  description = "Key rotation period in days (between 90 and 2560)"
  default     = 90
}

variable "ecs_task_execution_role_arn" {
  type        = string
  description = "ARN of the ECS task execution role"
  default     = ""
}

variable "ecs_task_role_arn" {
  type        = string
  description = "ARN of the ECS task role"
  default     = ""
}

variable "batch_instance_role_arn" {
  type        = string
  description = "ARN of the AWS Batch EC2 instance role"
  default     = ""
}

variable "key_admin_arns" {
  type        = list(string)
  description = "Optional additional principal ARNs with key administrative privileges"
  default     = []
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_iam_policy_document" "kms_forensic_vault" {
  statement {
    sid    = "EnableRootAccountAdministration"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.key_admin_arns) > 0 ? [1] : []
    content {
      sid    = "KeyAdministratorAccess"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = var.key_admin_arns
      }

      actions = [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ]

      resources = ["*"]
    }
  }

  statement {
    sid    = "AllowS3AndEventBridgeEncryptionUsage"
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = [
        "s3.amazonaws.com",
        "events.amazonaws.com"
      ]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogsEncryption"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.region}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]

    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/ecs/${var.project_prefix}-*"]
    }
  }

  statement {
    sid    = "AllowCloudTrailLogEncryption"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(compact([var.ecs_task_execution_role_arn, var.ecs_task_role_arn, var.batch_instance_role_arn])) > 0 ? [1] : []
    content {
      sid    = "AllowComputeRolesKeyUsage"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = compact([var.ecs_task_execution_role_arn, var.ecs_task_role_arn, var.batch_instance_role_arn])
      }

      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]

      resources = ["*"]
    }
  }
}

resource "aws_kms_key" "forensic_vault" {
  count                   = var.create_kms_key ? 1 : 0
  description             = "dfirbaboon Forensic Evidence Encryption Key"
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = true
  rotation_period_in_days = var.rotation_period_in_days
  policy                  = data.aws_iam_policy_document.kms_forensic_vault.json

  tags = {
    Name = "${var.project_prefix}-forensic-cmk"
  }
}

resource "aws_kms_alias" "forensic_vault" {
  count         = var.create_kms_key ? 1 : 0
  name          = "alias/${var.project_prefix}-forensic-key"
  target_key_id = aws_kms_key.forensic_vault[0].key_id
}

output "key_arn" {
  description = "ARN of the forensic KMS CMK (created or pre-existing)"
  value       = var.create_kms_key ? aws_kms_key.forensic_vault[0].arn : var.existing_kms_key_arn
}

output "key_id" {
  description = "Key ID of the forensic KMS CMK"
  value       = var.create_kms_key ? aws_kms_key.forensic_vault[0].key_id : null
}

output "alias_arn" {
  description = "ARN of the KMS alias"
  value       = var.create_kms_key ? aws_kms_alias.forensic_vault[0].arn : null
}

output "alias_name" {
  description = "Name of the KMS alias"
  value       = var.create_kms_key ? aws_kms_alias.forensic_vault[0].name : null
}
