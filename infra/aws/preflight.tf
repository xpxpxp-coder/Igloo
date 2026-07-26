data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  workload_name = "snowman-command-center-${var.environment}"
}

resource "terraform_data" "production_boundary_preflight" {
  input = {
    account_id = data.aws_caller_identity.current.account_id
    image      = var.container_image
    stage      = var.environment
  }

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.expected_workload_account_id
      error_message = "The active AWS caller is not in the exact approved Command Center workload account."
    }

    precondition {
      condition     = var.expected_workload_account_id != var.management_account_id
      error_message = "Snowman Command Center workloads can never deploy into the Organizations management account."
    }

    precondition {
      condition = (
        var.environment != "production" ||
        var.expected_workload_account_id != var.analyst360_workload_account_id
      )
      error_message = "Production Command Center and Analyst 360 workload authority must use separate AWS accounts."
    }

    precondition {
      condition = startswith(
        var.container_image,
        "${var.expected_workload_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/snowman-command-center@sha256:"
      )
      error_message = "The image digest must come from the exact Snowman workload account and region."
    }

    precondition {
      condition = (
        var.environment != "staging" ||
        (var.relay_desired_count == 0 && var.worker_desired_count == 0 && var.model_gateway_desired_count == 0)
      )
      error_message = "Staging remains dormant in baseline Terraform; verification windows use a reviewed override plan."
    }

    precondition {
      condition = (
        var.environment != "production" ||
        (var.relay_desired_count >= 2 && var.worker_desired_count >= 2 && var.model_gateway_desired_count >= 2)
      )
      error_message = "Production requires at least two tasks for every critical service."
    }

    precondition {
      condition     = !var.external_model_processors_enabled
      error_message = "External model processors are disabled until a provider/data-class approval is implemented."
    }
  }
}
