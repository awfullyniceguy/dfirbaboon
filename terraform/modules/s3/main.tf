variable "project_prefix" {
  type        = string
  description = "Project resource naming prefix"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS Key ARN for server-side encryption"
}

variable "intake_retention_days" {
  type        = number
  description = "Expiration period in days for raw evidence in the intake bucket"
  default     = 7
}

variable "create_intake_bucket" {
  type        = bool
  description = "Whether to create the intake S3 bucket. Set to false if using an existing pre-vended bucket."
  default     = true
}

variable "existing_intake_bucket_name" {
  type        = string
  description = "Name of pre-existing intake S3 bucket if create_intake_bucket is false"
  default     = null
}

variable "existing_intake_bucket_arn" {
  type        = string
  description = "ARN of pre-existing intake S3 bucket if create_intake_bucket is false"
  default     = null
}

variable "create_audit_trail_bucket" {
  type        = bool
  description = "Whether to create the CloudTrail audit log S3 bucket. Set to false if using an existing audit bucket."
  default     = true
}

variable "existing_audit_trail_bucket_id" {
  type        = string
  description = "Name or ID of pre-existing CloudTrail audit log S3 bucket if create_audit_trail_bucket is false"
  default     = null
}

variable "existing_audit_trail_bucket_arn" {
  type        = string
  description = "ARN of pre-existing CloudTrail audit log S3 bucket if create_audit_trail_bucket is false"
  default     = null
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# -----------------------------------------------------------------------------
# 1. Forensic Intake S3 Bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "intake" {
  count         = var.create_intake_bucket ? 1 : 0
  bucket        = "${var.project_prefix}-intake-${local.account_id}"
  force_destroy = false

  tags = {
    Name        = "${var.project_prefix}-intake"
    Environment = "Forensic-Intake"
  }
}

resource "aws_s3_bucket_versioning" "intake" {
  count  = var.create_intake_bucket ? 1 : 0
  bucket = aws_s3_bucket.intake[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "intake" {
  count  = var.create_intake_bucket ? 1 : 0
  bucket = aws_s3_bucket.intake[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "intake" {
  count  = var.create_intake_bucket ? 1 : 0
  bucket = aws_s3_bucket.intake[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "intake" {
  count  = var.create_intake_bucket ? 1 : 0
  bucket = aws_s3_bucket.intake[0].id

  rule {
    id     = "expire-processed-intake-evidence"
    status = "Enabled"

    expiration {
      days = var.intake_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.intake_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.intake]
}

resource "aws_s3_bucket_notification" "intake" {
  count       = var.create_intake_bucket ? 1 : 0
  bucket      = aws_s3_bucket.intake[0].id
  eventbridge = true
}

data "aws_iam_policy_document" "intake_tls_enforced" {
  count = var.create_intake_bucket ? 1 : 0

  statement {
    sid     = "EnforceTLSRequestsOnly"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.intake[0].arn,
      "${aws_s3_bucket.intake[0].arn}/*"
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "intake" {
  count  = var.create_intake_bucket ? 1 : 0
  bucket = aws_s3_bucket.intake[0].id
  policy = data.aws_iam_policy_document.intake_tls_enforced[0].json

  depends_on = [aws_s3_bucket_public_access_block.intake]
}

# -----------------------------------------------------------------------------
# 2. CloudTrail Audit Trail Storage S3 Bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "audit_trail" {
  count         = var.create_audit_trail_bucket ? 1 : 0
  bucket        = "${var.project_prefix}-audit-trail-${local.account_id}"
  force_destroy = false

  tags = {
    Name        = "${var.project_prefix}-audit-trail"
    Environment = "Forensic-Audit"
  }
}

resource "aws_s3_bucket_versioning" "audit_trail" {
  count  = var.create_audit_trail_bucket ? 1 : 0
  bucket = aws_s3_bucket.audit_trail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_trail" {
  count  = var.create_audit_trail_bucket ? 1 : 0
  bucket = aws_s3_bucket.audit_trail[0].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_trail" {
  count  = var.create_audit_trail_bucket ? 1 : 0
  bucket = aws_s3_bucket.audit_trail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "audit_trail_bucket_policy" {
  count = var.create_audit_trail_bucket ? 1 : 0

  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit_trail[0].arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit_trail[0].arn}/AWSLogs/${local.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "EnforceTLSRequestsOnly"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.audit_trail[0].arn,
      "${aws_s3_bucket.audit_trail[0].arn}/*"
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_trail" {
  count  = var.create_audit_trail_bucket ? 1 : 0
  bucket = aws_s3_bucket.audit_trail[0].id
  policy = data.aws_iam_policy_document.audit_trail_bucket_policy[0].json

  depends_on = [aws_s3_bucket_public_access_block.audit_trail]
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "intake_bucket_id" {
  value = var.create_intake_bucket ? aws_s3_bucket.intake[0].id : var.existing_intake_bucket_name
}

output "intake_bucket_name" {
  value = var.create_intake_bucket ? aws_s3_bucket.intake[0].id : var.existing_intake_bucket_name
}

output "intake_bucket_arn" {
  value = var.create_intake_bucket ? aws_s3_bucket.intake[0].arn : (
    var.existing_intake_bucket_arn != null ? var.existing_intake_bucket_arn : "arn:aws:s3:::${var.existing_intake_bucket_name}"
  )
}

output "audit_trail_bucket_id" {
  value = var.create_audit_trail_bucket ? aws_s3_bucket.audit_trail[0].id : var.existing_audit_trail_bucket_id
}

output "audit_trail_bucket_name" {
  value = var.create_audit_trail_bucket ? aws_s3_bucket.audit_trail[0].id : var.existing_audit_trail_bucket_id
}

output "audit_trail_bucket_arn" {
  value = var.create_audit_trail_bucket ? aws_s3_bucket.audit_trail[0].arn : (
    var.existing_audit_trail_bucket_arn != null ? var.existing_audit_trail_bucket_arn : "arn:aws:s3:::${var.existing_audit_trail_bucket_id}"
  )
}
