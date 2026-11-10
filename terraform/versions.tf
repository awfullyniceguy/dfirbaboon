terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.38.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_prefix
      ManagedBy   = "Terraform"
      Application = "dfirbaboon-serverless-dfir"
      Repository  = "https://github.com/awfullyniceguy/dfirbaboon"
    }
  }
}
