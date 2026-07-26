terraform {
  required_version = "= 1.15.8"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.56.0"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = "= 1.94.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.expected_workload_account_id]

  default_tags {
    tags = local.tags
  }
}

provider "awscc" {
  region = var.aws_region
}
