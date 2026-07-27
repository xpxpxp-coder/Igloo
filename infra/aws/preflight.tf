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
        (var.relay_desired_count == 0 && var.worker_desired_count == 0 && var.scheduler_desired_count == 0 && var.trigger_desired_count == 0 && var.reminder_desired_count == 0 && var.agent_broker_desired_count == 0 && var.agent_coordinator_desired_count == 0 && var.model_gateway_desired_count == 0 && var.meeting_command_desired_count == 0 && var.meeting_media_desired_count == 0)
      )
      error_message = "Staging remains dormant in baseline Terraform; verification windows use a reviewed override plan."
    }

    precondition {
      condition = (
        var.relay_desired_count == 0 &&
        var.worker_desired_count == 0 &&
        var.scheduler_desired_count == 0 &&
        var.trigger_desired_count == 0 &&
        var.reminder_desired_count == 0 &&
        var.agent_broker_desired_count == 0 &&
        var.agent_coordinator_desired_count == 0 &&
        var.model_gateway_desired_count == 0 &&
        var.meeting_command_desired_count == 0 &&
        var.meeting_media_desired_count == 0 &&
        !var.meeting_external_provider_egress_enabled &&
        !var.workforce_private_ingress_enabled &&
        !var.workforce_api_enabled &&
        !var.workforce_worker_api_enabled &&
        !var.analyst_event_api_enabled
      )
      error_message = "Runtime desired counts remain hard-zero, external meeting-provider egress remains disabled, and private workforce ingress/APIs remain hard-disabled until the staged activation contracts pass."
    }

    precondition {
      condition     = !var.external_model_processors_enabled
      error_message = "External model processors are disabled until a provider/data-class approval is implemented."
    }

    precondition {
      condition     = alltrue([for zone in var.availability_zones : startswith(zone, var.aws_region)])
      error_message = "Every availability zone must belong to the exact workload region."
    }

    precondition {
      condition = startswith(
        var.acm_certificate_arn,
        "arn:${data.aws_partition.current.partition}:acm:${var.aws_region}:${var.expected_workload_account_id}:certificate/"
      )
      error_message = "The ACM certificate must belong to the exact workload account and region."
    }

    precondition {
      condition     = var.deletion_protection
      error_message = "Managed Snowman state must keep deletion protection enabled."
    }

    precondition {
      condition     = var.environment != "production" || var.backup_retention_days == 35
      error_message = "Production requires the maximum 35-day managed snapshot retention window."
    }

    precondition {
      condition     = var.environment != "production" || var.audit_retention_days >= 2555
      error_message = "Production audit checkpoints require at least seven years of object-lock retention."
    }
  }
}
