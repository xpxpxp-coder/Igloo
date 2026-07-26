terraform {
  required_version = "= 1.15.8"

  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.expected_workload_account_id]

  default_tags {
    tags = {
      Application   = "snowman-command-center"
      Environment   = var.environment
      Owner         = "snowman-ai"
      ManagedBy     = "terraform"
      DataAuthority = "command-center-only"
      Soc2Scope     = "governed-agent-operations"
    }
  }
}
