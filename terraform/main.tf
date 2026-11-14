# =============================================================================
# DFIR Baboon: Serverless Cloud-Native Forensic Pipeline
# Root Infrastructure Composition (Supports Simple & Compliance Modes + BYO)
# =============================================================================

locals {
  is_compliance = var.forensic_mode == "compliance"

  effective_create_kms_key            = coalesce(var.create_kms_key, local.is_compliance)
  effective_create_audit_trail_bucket = coalesce(var.create_audit_trail_bucket, local.is_compliance)
  effective_create_cloudtrail         = coalesce(var.create_cloudtrail, local.is_compliance)
  effective_log_retention_days        = coalesce(var.cloudwatch_log_retention_days, local.is_compliance ? 90 : 7)
  effective_force_destroy             = !local.is_compliance
}

# 1. Forensic KMS Customer Managed Key (CMK) with 90-Day Rotation (Compliance Mode)
module "kms" {
  source = "./modules/kms"

  project_prefix          = var.project_prefix
  create_kms_key          = local.effective_create_kms_key
  existing_kms_key_arn    = var.existing_kms_key_arn
  deletion_window_in_days = var.kms_deletion_window_in_days
  rotation_period_in_days = var.kms_rotation_period_in_days
  key_admin_arns          = var.kms_key_admin_arns
}

# 2. S3 Storage Architecture (Intake & Optional Immutable CloudTrail Audit Trail)
module "s3" {
  source = "./modules/s3"

  project_prefix                  = var.project_prefix
  kms_key_arn                     = module.kms.key_arn
  force_destroy                   = local.effective_force_destroy
  enable_object_lock              = local.is_compliance
  intake_retention_days           = var.intake_retention_days
  create_intake_bucket            = var.create_intake_bucket
  existing_intake_bucket_name     = var.existing_intake_bucket_name
  existing_intake_bucket_arn      = var.existing_intake_bucket_arn
  create_audit_trail_bucket       = local.effective_create_audit_trail_bucket
  existing_audit_trail_bucket_id  = var.existing_audit_trail_bucket_id
  existing_audit_trail_bucket_arn = var.existing_audit_trail_bucket_arn
}

# 3. VPC Networking & Private S3 Gateway Endpoint
module "network" {
  source = "./modules/network"

  project_prefix             = var.project_prefix
  vpc_id                     = var.vpc_id
  subnet_ids                 = var.subnet_ids
  create_s3_vpc_endpoint     = var.create_s3_vpc_endpoint
  create_security_group      = var.create_security_group
  existing_security_group_id = var.existing_security_group_id
}

# 4. Least-Privilege IAM Roles & Security Boundaries
module "iam" {
  source = "./modules/iam"

  project_prefix                       = var.project_prefix
  intake_bucket_arn                    = module.s3.intake_bucket_arn
  kms_key_arn                          = module.kms.key_arn
  vault_bucket_arn                     = var.vault_bucket_arn
  create_iam_roles                     = var.create_iam_roles
  permissions_boundary_arn             = var.permissions_boundary_arn
  existing_ecs_task_execution_role_arn = var.existing_ecs_task_execution_role_arn
  existing_ecs_task_role_arn           = var.existing_ecs_task_role_arn
  existing_batch_instance_role_arn     = var.existing_batch_instance_role_arn
  existing_batch_instance_profile_arn  = var.existing_batch_instance_profile_arn
  existing_eventbridge_invoke_role_arn = var.existing_eventbridge_invoke_role_arn
}

# 5. Monitoring, CloudWatch Logs, Audit Trail & Metric Alarms
module "monitoring" {
  source = "./modules/monitoring"

  project_prefix          = var.project_prefix
  kms_key_arn             = module.kms.key_arn
  log_retention_days      = local.effective_log_retention_days
  audit_trail_bucket_id   = module.s3.audit_trail_bucket_id
  intake_bucket_arn       = module.s3.intake_bucket_arn
  vault_bucket_arn        = var.vault_bucket_arn
  ecs_cluster_name        = "${var.project_prefix}-cluster"
  batch_job_queue_arn     = module.compute.batch_job_queue_arn
  create_cloudtrail       = local.effective_create_cloudtrail
  create_log_group        = var.create_log_group
  existing_log_group_name = var.existing_log_group_name
}

# 6. Compute Engines (ECS Fargate & AWS Batch on EC2 with Local NVMe)
module "compute" {
  source = "./modules/compute"

  project_prefix              = var.project_prefix
  forensic_mode               = var.forensic_mode
  force_destroy               = local.effective_force_destroy
  kms_key_arn                 = module.kms.key_arn
  worker_image_tag            = var.worker_image_tag
  fargate_cpu                 = var.fargate_cpu
  fargate_memory              = var.fargate_memory
  ephemeral_storage_gib       = var.ephemeral_storage_gib
  batch_instance_types        = var.batch_instance_types
  batch_vcpus                 = var.batch_vcpus
  batch_memory_mib            = var.batch_memory_mib
  batch_scratch_gib           = var.batch_scratch_gib
  batch_job_timeout_hours     = var.batch_job_timeout_hours
  subnet_ids                  = module.network.subnet_ids
  security_group_id           = module.network.security_group_id
  ecs_task_execution_role_arn = module.iam.ecs_task_execution_role_arn
  ecs_task_role_arn           = module.iam.ecs_task_role_arn
  batch_instance_profile_arn  = module.iam.batch_instance_profile_arn
  cloudwatch_log_group_name   = module.monitoring.log_group_name
  create_ecr_repository       = var.create_ecr_repository
  existing_ecr_repository_url = var.existing_ecr_repository_url
  create_vault_bucket         = var.create_vault_bucket
  vault_bucket_name           = var.vault_bucket_name
  vault_prefix                = var.vault_prefix
}

# 7. EventBridge Dual Size-Routing Rules (<= 50 GiB vs > 50 GiB)
module "events" {
  source = "./modules/events"

  project_prefix              = var.project_prefix
  intake_bucket_name          = module.s3.intake_bucket_name
  large_image_threshold_gib   = var.large_image_threshold_gib
  ecs_cluster_arn             = module.compute.ecs_cluster_arn
  ecs_task_definition_arn     = module.compute.ecs_task_definition_arn
  subnet_ids                  = module.network.subnet_ids
  security_group_id           = module.network.security_group_id
  eventbridge_invoke_role_arn = module.iam.eventbridge_invoke_role_arn
  batch_job_queue_arn         = module.compute.batch_job_queue_arn
  batch_job_definition_arn    = module.compute.batch_job_definition_arn
  enable_event_rules          = var.enable_event_rules
}
