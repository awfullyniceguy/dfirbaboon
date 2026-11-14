variable "project_prefix" {
  type        = string
  description = "Resource name prefix for all dfirbaboon AWS infrastructure"
  default     = "dfirbaboon"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_prefix))
    error_message = "project_prefix must contain only lowercase alphanumeric characters and hyphens."
  }
}

variable "forensic_mode" {
  type        = string
  description = "Deployment mode: 'simple' (default, rapid testing & clean teardown without Object Lock/KMS CMK/CloudTrail) or 'compliance' (full evidence locks, KMS CMK, CloudTrail, retention)."
  default     = "simple"

  validation {
    condition     = contains(["simple", "compliance"], var.forensic_mode)
    error_message = "forensic_mode must be either 'simple' or 'compliance'."
  }
}

variable "aws_region" {
  type        = string
  description = "Target AWS Region for deployment"
  default     = "us-east-1"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where the ECS tasks and Batch workers run. If null, uses default VPC."
  default     = null
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnet IDs for task and worker networking. If empty, uses subnets in default VPC."
  default     = []
}

variable "worker_image_tag" {
  type        = string
  description = "Tag of the worker Docker image to run"
  default     = "latest"
}

variable "fargate_cpu" {
  type        = number
  description = "vCPU allocation for Fargate task (4096 = 4 vCPU)"
  default     = 4096
}

variable "fargate_memory" {
  type        = number
  description = "Memory allocation for Fargate task in MiB (8192 = 8 GB)"
  default     = 8192
}

variable "ephemeral_storage_gib" {
  type        = number
  description = "Ephemeral storage size in GiB for Fargate worker (21 to 200 GiB)"
  default     = 100

  validation {
    condition     = var.ephemeral_storage_gib >= 21 && var.ephemeral_storage_gib <= 200
    error_message = "ephemeral_storage_gib must be between 21 and 200 GiB for AWS Fargate."
  }
}

variable "large_image_threshold_gib" {
  type        = number
  description = "Evidence size boundary in GiB. <= routes to Fargate, > routes to AWS Batch on EC2."
  default     = 50
}

variable "intake_retention_days" {
  type        = number
  description = "Retention period in days for raw evidence in intake bucket before expiration"
  default     = 7
}

variable "batch_instance_types" {
  type        = list(string)
  description = "EC2 instance types for large Batch jobs (equipped with local NVMe SSDs)"
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
  description = "Maximum execution duration for large Batch jobs in hours"
  default     = 48
}

variable "kms_deletion_window_in_days" {
  type        = number
  description = "KMS key deletion waiting period in days"
  default     = 30
}

variable "kms_rotation_period_in_days" {
  type        = number
  description = "KMS automatic key rotation period in days (90 to 2560)"
  default     = 90
}

variable "kms_key_admin_arns" {
  type        = list(string)
  description = "Optional additional principal ARNs with key administrative privileges"
  default     = []
}

variable "cloudwatch_log_retention_days" {
  type        = number
  description = "Log retention period in days for CloudWatch log groups (defaults to 7 in simple mode, 90 in compliance mode)"
  default     = null
}

# -----------------------------------------------------------------------------
# Enterprise / Controlled Environment BYO ("Bring Your Own") Component Toggles
# -----------------------------------------------------------------------------

variable "create_kms_key" {
  type        = bool
  description = "Whether to create a new KMS CMK. Defaults to true in compliance mode and false in simple mode."
  default     = null
}

variable "existing_kms_key_arn" {
  type        = string
  description = "ARN of pre-existing KMS CMK if create_kms_key is false"
  default     = null
}

variable "create_intake_bucket" {
  type        = bool
  description = "Whether to create the S3 intake bucket. Set to false when using a pre-vended intake bucket."
  default     = true
}

variable "intake_bucket_name" {
  type        = string
  description = "Optional custom name for the S3 intake bucket when create_intake_bucket is true. Defaults to '<project_prefix>-intake-<account_id>'."
  default     = null

  validation {
    condition     = var.intake_bucket_name == null || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.intake_bucket_name))
    error_message = "intake_bucket_name must be a valid S3 bucket name (3-63 lowercase letters, numbers, hyphens, or periods)."
  }
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
  description = "Whether to create the CloudTrail audit log S3 bucket. Defaults to true in compliance mode and false in simple mode."
  default     = null
}

variable "existing_audit_trail_bucket_id" {
  type        = string
  description = "Name/ID of pre-existing CloudTrail audit log S3 bucket if create_audit_trail_bucket is false"
  default     = null
}

variable "existing_audit_trail_bucket_arn" {
  type        = string
  description = "ARN of pre-existing CloudTrail audit log S3 bucket if create_audit_trail_bucket is false"
  default     = null
}

variable "create_vault_bucket" {
  type        = bool
  description = "Whether the worker creates incident vault buckets at runtime. Set to false if vault buckets are pre-vended."
  default     = true
}

variable "vault_bucket_name" {
  type        = string
  description = "Optional pre-provisioned central vault bucket name (e.g. corp-forensics-evidence-lake)"
  default     = null
}

variable "vault_bucket_arn" {
  type        = string
  description = "Optional ARN of pre-provisioned central vault bucket"
  default     = null
}

variable "vault_prefix" {
  type        = string
  description = "Optional key prefix for central evidence vault (e.g. 'incidents/{incident_id}/')"
  default     = null
}

variable "create_iam_roles" {
  type        = bool
  description = "Whether to create IAM roles. Set to false if roles are pre-vended by IAM team or account factory."
  default     = true
}

variable "permissions_boundary_arn" {
  type        = string
  description = "Optional IAM permissions boundary ARN mandated by enterprise landing zone policy"
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

variable "create_s3_vpc_endpoint" {
  type        = bool
  description = "Whether to create S3 Gateway VPC endpoint. Set to false if VPC already has one."
  default     = true
}

variable "create_security_group" {
  type        = bool
  description = "Whether to create worker security group. Set to false if using pre-existing security group."
  default     = true
}

variable "existing_security_group_id" {
  type        = string
  description = "Pre-existing security group ID if create_security_group is false"
  default     = null
}

variable "create_ecr_repository" {
  type        = bool
  description = "Whether to create ECR repository for worker container image"
  default     = true
}

variable "existing_ecr_repository_url" {
  type        = string
  description = "Pre-existing ECR repository URL if create_ecr_repository is false"
  default     = null
}

variable "create_cloudtrail" {
  type        = bool
  description = "Whether to create dedicated forensic CloudTrail trail. Defaults to true in compliance mode and false in simple mode."
  default     = null
}

variable "create_log_group" {
  type        = bool
  description = "Whether to create CloudWatch log group. Set to false if using pre-existing log group."
  default     = true
}

variable "existing_log_group_name" {
  type        = string
  description = "Name of pre-existing CloudWatch log group if create_log_group is false"
  default     = null
}

variable "enable_event_rules" {
  type        = bool
  description = "Whether to deploy automated EventBridge intake routing rules"
  default     = true
}
