variable "aws_region" {
  type        = string
  description = "Snowman inference workload region."
}

variable "environment" {
  type        = string
  description = "Deployment stage."
  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment must be staging or production."
  }
}

variable "expected_workload_account_id" {
  type        = string
  description = "Exact Snowman Command Center workload account."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_workload_account_id))
    error_message = "expected_workload_account_id must be a 12-digit account ID."
  }
}

variable "management_account_id" {
  type        = string
  description = "Snowman management account, which may not host inference."
}

variable "analyst360_workload_account_id" {
  type        = string
  description = "Separate Analyst 360 workload account."
}

variable "foundation_enabled" {
  type        = bool
  default     = false
  description = "Create only the encrypted model-artifact and execution-role foundation."
}

variable "endpoints_enabled" {
  type        = bool
  default     = false
  description = "Create private network-isolated SageMaker endpoints and inference components."
}

variable "activation_approved" {
  type        = bool
  default     = false
  description = "Explicit staged activation gate after image, artifact, evaluation, quota, and cost evidence is reviewed."
}

variable "private_subnet_ids" {
  type        = set(string)
  default     = []
  description = "Exact private Snowman subnets exported by the Command Center root."
  validation {
    condition = !var.endpoints_enabled || (
      length(var.private_subnet_ids) >= 2 &&
      alltrue([for id in var.private_subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", id))])
    )
    error_message = "Active endpoints require at least two exact private subnet IDs."
  }
}

variable "inference_security_group_id" {
  type        = string
  default     = ""
  description = "Exact Snowman inference security group exported by the Command Center root."
  validation {
    condition     = !var.endpoints_enabled || can(regex("^sg-[0-9a-f]{8,17}$", var.inference_security_group_id))
    error_message = "Active endpoints require an exact inference security group ID."
  }
}

variable "operations_sns_topic_arn" {
  type        = string
  default     = ""
  description = "Exact monitored Snowman operations topic used for inference alarms."
  validation {
    condition = !var.endpoints_enabled || can(regex(
      "^arn:aws[a-z-]*:sns:[a-z0-9-]+:${var.expected_workload_account_id}:[A-Za-z0-9_-]+$",
      var.operations_sns_topic_arn
    ))
    error_message = "Active endpoints require an exact same-account monitored SNS topic."
  }
}

variable "monthly_inference_budget_usd" {
  type        = number
  default     = 250
  description = "Monthly tag-scoped inference cost budget."
  validation {
    condition     = var.monthly_inference_budget_usd >= 10 && var.monthly_inference_budget_usd <= 10000
    error_message = "monthly_inference_budget_usd must be between 10 and 10000."
  }
}

variable "models" {
  description = "Pinned Snowman-hosted specialist model fleet. Keys are short stable catalog families."
  type = map(object({
    endpoint_name                     = string
    inference_component_name          = string
    container_image                   = string
    artifact_key                      = string
    artifact_sha256                   = string
    instance_type                     = string
    max_instances                     = number
    max_copies                        = number
    cpu_cores_required                = number
    accelerator_devices_required      = number
    min_memory_required_mb            = number
    max_memory_required_mb            = number
    model_download_timeout_seconds    = optional(number, 1800)
    container_startup_timeout_seconds = optional(number, 1800)
  }))
  default = {}

  validation {
    condition = alltrue([
      for family, model in var.models :
      can(regex("^[a-z0-9][a-z0-9-]{1,23}$", family)) &&
      can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", model.endpoint_name)) &&
      can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", model.inference_component_name)) &&
      can(regex("^[0-9]{12}[.]dkr[.]ecr[.][a-z0-9-]+[.]amazonaws[.]com/snowman-inference/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", model.container_image)) &&
      startswith(model.container_image, "${var.expected_workload_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/") &&
      can(regex("^[a-zA-Z0-9][a-zA-Z0-9._/-]*-[0-9a-f]{64}[.]tar[.]gz$", model.artifact_key)) &&
      can(regex("^[0-9a-f]{64}$", model.artifact_sha256)) &&
      strcontains(model.artifact_key, model.artifact_sha256) &&
      can(regex("^ml[.](g5|g6|g6e|inf2|p4d|p5)[.][a-z0-9]+$", model.instance_type)) &&
      model.max_instances >= 1 && model.max_instances <= 4 &&
      model.max_copies >= 1 && model.max_copies <= 8 &&
      model.cpu_cores_required >= 1 && model.cpu_cores_required <= 192 &&
      model.accelerator_devices_required >= 1 && model.accelerator_devices_required <= 8 &&
      model.min_memory_required_mb >= 1024 &&
      model.max_memory_required_mb >= model.min_memory_required_mb &&
      model.max_memory_required_mb <= 1048576 &&
      model.model_download_timeout_seconds >= 60 && model.model_download_timeout_seconds <= 3600 &&
      model.container_startup_timeout_seconds >= 60 && model.container_startup_timeout_seconds <= 3600
    ])
    error_message = "Each model must use unique bounded coordinates, digest-pinned Snowman ECR, content-addressed weights, and bounded GPU capacity."
  }
}
