variable "project_prefix" {
  type        = string
  description = "Project resource naming prefix"
}

variable "intake_bucket_arn" {
  type        = string
  description = "ARN of the intake S3 bucket"
}

variable "kms_key_arn" {
  type        = string
  description = "Optional ARN of the KMS CMK (null in simple mode without CMK)"
  default     = null
}

variable "vault_bucket_arn" {
  type        = string
  description = "Optional ARN of pre-provisioned central forensic vault bucket or evidence lake"
  default     = null
}

variable "create_iam_roles" {
  type        = bool
  description = "Whether to create IAM roles. Set to false in environments where roles are pre-vended."
  default     = true
}

variable "permissions_boundary_arn" {
  type        = string
  description = "Optional IAM permissions boundary ARN mandated by enterprise landing zone"
  default     = null
}

variable "existing_ecs_task_execution_role_arn" {
  type        = string
  description = "Pre-existing ECS task execution role ARN if create_iam_roles is false"
  default     = null
}

variable "existing_ecs_task_role_arn" {
  type        = string
  description = "Pre-existing ECS task role ARN if create_iam_roles is false"
  default     = null
}

variable "existing_batch_instance_role_arn" {
  type        = string
  description = "Pre-existing AWS Batch EC2 instance role ARN if create_iam_roles is false"
  default     = null
}

variable "existing_batch_instance_profile_arn" {
  type        = string
  description = "Pre-existing AWS Batch EC2 instance profile ARN if create_iam_roles is false"
  default     = null
}

variable "existing_eventbridge_invoke_role_arn" {
  type        = string
  description = "Pre-existing EventBridge invocation role ARN if create_iam_roles is false"
  default     = null
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  use_kms    = var.kms_key_arn != null && var.kms_key_arn != ""

  vault_bucket_resources = compact([
    "arn:aws:s3:::${var.project_prefix}-inc*",
    var.vault_bucket_arn
  ])

  vault_object_resources = compact([
    "arn:aws:s3:::${var.project_prefix}-inc*/*",
    var.vault_bucket_arn != null ? "${var.vault_bucket_arn}/*" : null
  ])
}

# -----------------------------------------------------------------------------
# 1. ECS Task Execution Role
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_execution" {
  count                = var.create_iam_roles ? 1 : 0
  name                 = "${var.project_prefix}-ecs-execution-role"
  assume_role_policy   = data.aws_iam_policy_document.ecs_task_assume_role.json
  permissions_boundary = var.permissions_boundary_arn

  tags = {
    Name = "${var.project_prefix}-ecs-execution-role"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_managed" {
  count      = var.create_iam_roles ? 1 : 0
  role       = aws_iam_role.ecs_task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_task_execution_kms" {
  count = var.create_iam_roles && local.use_kms ? 1 : 0

  statement {
    sid    = "AllowKMSForECRAndLogs"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey*"
    ]

    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "ecs_task_execution_kms" {
  count  = var.create_iam_roles && local.use_kms ? 1 : 0
  name   = "${var.project_prefix}-ecs-execution-kms-policy"
  role   = aws_iam_role.ecs_task_execution[0].id
  policy = data.aws_iam_policy_document.ecs_task_execution_kms[0].json
}

# -----------------------------------------------------------------------------
# 2. ECS Task Role (Forensic Worker)
# -----------------------------------------------------------------------------

resource "aws_iam_role" "ecs_task" {
  count                = var.create_iam_roles ? 1 : 0
  name                 = "${var.project_prefix}-ecs-task-role"
  assume_role_policy   = data.aws_iam_policy_document.ecs_task_assume_role.json
  permissions_boundary = var.permissions_boundary_arn

  tags = {
    Name = "${var.project_prefix}-ecs-task-role"
  }
}

data "aws_iam_policy_document" "ecs_task_permissions" {
  count = var.create_iam_roles ? 1 : 0

  statement {
    sid    = "ReadIntakeEvidenceBucket"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:HeadObject",
      "s3:ListBucket",
      "s3:GetBucketLocation"
    ]

    resources = [
      var.intake_bucket_arn,
      "${var.intake_bucket_arn}/*"
    ]
  }

  statement {
    sid    = "ProvisionAndManageIncidentVaultBuckets"
    effect = "Allow"

    actions = [
      "s3:CreateBucket",
      "s3:HeadBucket",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:PutBucketVersioning",
      "s3:GetBucketVersioning",
      "s3:PutBucketObjectLockConfiguration",
      "s3:GetBucketObjectLockConfiguration",
      "s3:PutEncryptionConfiguration",
      "s3:GetEncryptionConfiguration",
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPolicy",
      "s3:GetBucketPolicy",
      "s3:PutBucketTagging",
      "s3:GetBucketTagging",
      "s3:PutLifecycleConfiguration"
    ]

    resources = local.vault_bucket_resources
  }

  statement {
    sid    = "WriteAndPreserveEvidenceInIncidentVaults"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:HeadObject",
      "s3:PutObjectRetention",
      "s3:GetObjectRetention",
      "s3:PutObjectLegalHold",
      "s3:GetObjectLegalHold",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts"
    ]

    resources = local.vault_object_resources
  }

  dynamic "statement" {
    for_each = local.use_kms ? [1] : []
    content {
      sid    = "KMSVaultEncryptionAccess"
      effect = "Allow"

      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]

      resources = [var.kms_key_arn]
    }
  }

  statement {
    sid    = "STSIdentityCheck"
    effect = "Allow"

    actions = [
      "sts:GetCallerIdentity"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ecs_task_permissions" {
  count  = var.create_iam_roles ? 1 : 0
  name   = "${var.project_prefix}-forensic-worker-policy"
  role   = aws_iam_role.ecs_task[0].id
  policy = data.aws_iam_policy_document.ecs_task_permissions[0].json
}

# -----------------------------------------------------------------------------
# 3. EventBridge Invocation Role
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "eventbridge_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eventbridge_invoke" {
  count                = var.create_iam_roles ? 1 : 0
  name                 = "${var.project_prefix}-eventbridge-invoke-role"
  assume_role_policy   = data.aws_iam_policy_document.eventbridge_assume_role.json
  permissions_boundary = var.permissions_boundary_arn

  tags = {
    Name = "${var.project_prefix}-eventbridge-invoke-role"
  }
}

data "aws_iam_policy_document" "eventbridge_invoke_tasks" {
  count = var.create_iam_roles ? 1 : 0

  statement {
    sid    = "AllowRunECSTask"
    effect = "Allow"

    actions = [
      "ecs:RunTask"
    ]

    resources = [
      "arn:aws:ecs:${data.aws_region.current.region}:${local.account_id}:task-definition/${var.project_prefix}-tsk-worker:*"
    ]
  }

  statement {
    sid    = "AllowPassRoleToECS"
    effect = "Allow"

    actions = [
      "iam:PassRole"
    ]

    resources = [
      aws_iam_role.ecs_task_execution[0].arn,
      aws_iam_role.ecs_task[0].arn
    ]
  }

  statement {
    sid    = "AllowSubmitBatchJob"
    effect = "Allow"

    actions = [
      "batch:SubmitJob"
    ]

    resources = [
      "arn:aws:batch:${data.aws_region.current.region}:${local.account_id}:job-queue/${var.project_prefix}-*",
      "arn:aws:batch:${data.aws_region.current.region}:${local.account_id}:job-definition/${var.project_prefix}-*:*"
    ]
  }
}

resource "aws_iam_role_policy" "eventbridge_invoke_tasks" {
  count  = var.create_iam_roles ? 1 : 0
  name   = "${var.project_prefix}-eventbridge-invoke-policy"
  role   = aws_iam_role.eventbridge_invoke[0].id
  policy = data.aws_iam_policy_document.eventbridge_invoke_tasks[0].json
}

# -----------------------------------------------------------------------------
# 4. AWS Batch EC2 Instance Role & Profile
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "batch_instance" {
  count                = var.create_iam_roles ? 1 : 0
  name                 = "${var.project_prefix}-batch-instance-role"
  assume_role_policy   = data.aws_iam_policy_document.ec2_assume_role.json
  permissions_boundary = var.permissions_boundary_arn

  tags = {
    Name = "${var.project_prefix}-batch-instance-role"
  }
}

resource "aws_iam_role_policy_attachment" "batch_instance_ecs" {
  count      = var.create_iam_roles ? 1 : 0
  role       = aws_iam_role.batch_instance[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "batch_instance" {
  count = var.create_iam_roles ? 1 : 0
  name  = "${var.project_prefix}-batch-instance-profile"
  role  = aws_iam_role.batch_instance[0].name
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "ecs_task_execution_role_arn" {
  value = var.create_iam_roles ? aws_iam_role.ecs_task_execution[0].arn : var.existing_ecs_task_execution_role_arn
}

output "ecs_task_role_arn" {
  value = var.create_iam_roles ? aws_iam_role.ecs_task[0].arn : var.existing_ecs_task_role_arn
}

output "batch_instance_role_arn" {
  value = var.create_iam_roles ? aws_iam_role.batch_instance[0].arn : var.existing_batch_instance_role_arn
}

output "batch_instance_profile_arn" {
  value = var.create_iam_roles ? aws_iam_instance_profile.batch_instance[0].arn : var.existing_batch_instance_profile_arn
}

output "eventbridge_invoke_role_arn" {
  value = var.create_iam_roles ? aws_iam_role.eventbridge_invoke[0].arn : var.existing_eventbridge_invoke_role_arn
}
