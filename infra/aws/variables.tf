variable "aws_region" {
  type        = string
  description = "AWS region for the isolated Snowman Command Center workload."
  default     = "us-west-2"
}

variable "environment" {
  type        = string
  description = "Exact deployment stage."
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "expected_workload_account_id" {
  type        = string
  description = "Exact Snowman workload account allowed to receive Command Center resources."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_workload_account_id))
    error_message = "expected_workload_account_id must be a 12-digit AWS account ID."
  }
}

variable "management_account_id" {
  type        = string
  description = "AWS Organizations management account, which must never host the workload."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be a 12-digit AWS account ID."
  }
}

variable "analyst360_workload_account_id" {
  type        = string
  description = "Analyst 360 workload account; production Command Center authority must remain separate."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.analyst360_workload_account_id))
    error_message = "analyst360_workload_account_id must be a 12-digit AWS account ID."
  }
}

variable "container_image" {
  type        = string
  description = "Immutable Snowman-owned ECR image URI and sha256 digest."
  validation {
    condition = can(regex(
      "^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/snowman-command-center@sha256:[0-9a-f]{64}$",
      var.container_image
    ))
    error_message = "container_image must be the Snowman ECR repository pinned by sha256 digest."
  }
}

variable "relay_desired_count" {
  type        = number
  description = "Desired relay tasks. Staging is dormant until an explicit verification window."
  default     = 0
  validation {
    condition     = var.relay_desired_count >= 0 && var.relay_desired_count <= 20
    error_message = "relay_desired_count must be between 0 and 20."
  }
}

variable "worker_desired_count" {
  type        = number
  description = "Desired durable workforce tasks."
  default     = 0
  validation {
    condition     = var.worker_desired_count >= 0 && var.worker_desired_count <= 100
    error_message = "worker_desired_count must be between 0 and 100."
  }
}

variable "model_gateway_desired_count" {
  type        = number
  description = "Desired Snowman model-gateway tasks."
  default     = 0
  validation {
    condition     = var.model_gateway_desired_count >= 0 && var.model_gateway_desired_count <= 20
    error_message = "model_gateway_desired_count must be between 0 and 20."
  }
}

variable "external_model_processors_enabled" {
  type        = bool
  description = "Fail-closed switch. Requires a future provider/data-class approval before it can become true."
  default     = false
}

variable "monthly_budget_usd" {
  type        = number
  description = "Account/service budget ceiling used by the AWS budget and runtime spend alarms."
  validation {
    condition     = var.monthly_budget_usd >= 10 && var.monthly_budget_usd <= 100000
    error_message = "monthly_budget_usd must be between 10 and 100000."
  }
}

variable "security_alert_email_endpoint" {
  type        = string
  description = "Monitored Snowman inbox for sanitized budget/security notifications."
  validation {
    condition     = can(regex("^[A-Za-z0-9._%+-]+@snowmanai\\.org$", var.security_alert_email_endpoint))
    error_message = "security_alert_email_endpoint must be a Snowman-controlled mailbox."
  }
}
