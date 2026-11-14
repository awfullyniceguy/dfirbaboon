# =============================================================================
# DFIR Baboon: Root Outputs
# =============================================================================

output "forensic_mode" {
  description = "Active deployment mode ('simple' or 'compliance')"
  value       = var.forensic_mode
}

output "kms_key_arn" {
  description = "ARN of the provisioned forensic KMS CMK"
  value       = module.kms.key_arn
}

output "intake_bucket_name" {
  description = "S3 intake bucket name for dropping raw evidence disk images"
  value       = module.s3.intake_bucket_name
}

output "intake_bucket_arn" {
  description = "ARN of the S3 intake bucket"
  value       = module.s3.intake_bucket_arn
}

output "audit_trail_bucket_name" {
  description = "S3 bucket storing CloudTrail audit logs for S3 and KMS events"
  value       = module.s3.audit_trail_bucket_name
}

output "cloudtrail_arn" {
  description = "ARN of the AWS CloudTrail trail capturing forensic data events"
  value       = module.monitoring.cloudtrail_arn
}

output "ecr_repository_url" {
  description = "ECR repository URI for the dfirbaboon worker container"
  value       = module.compute.ecr_repository_url
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.compute.ecs_cluster_name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = module.compute.ecs_cluster_arn
}

output "ecs_task_definition_arn" {
  description = "ARN of the ECS Fargate task definition"
  value       = module.compute.ecs_task_definition_arn
}

output "batch_job_queue_arn" {
  description = "ARN of the AWS Batch job queue for large images"
  value       = module.compute.batch_job_queue_arn
}

output "batch_job_definition_arn" {
  description = "ARN of the AWS Batch job definition for large images"
  value       = module.compute.batch_job_definition_arn
}

output "s3_vpc_endpoint_id" {
  description = "ID of the S3 Gateway VPC endpoint"
  value       = module.network.s3_vpc_endpoint_id
}

output "large_image_threshold_gib" {
  description = "Size routing boundary in GiB (<= routes to Fargate, > routes to Batch)"
  value       = var.large_image_threshold_gib
}
