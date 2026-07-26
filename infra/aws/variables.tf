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

variable "vpc_cidr" {
  type        = string
  description = "Dedicated Command Center VPC CIDR."
  default     = "10.72.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "availability_zones" {
  type        = list(string)
  description = "Three distinct workload availability zones in aws_region."
  validation {
    condition     = length(var.availability_zones) == 3 && length(toset(var.availability_zones)) == 3
    error_message = "availability_zones must contain exactly three distinct zones."
  }
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "Three ingress-only ALB subnet CIDRs."
  validation {
    condition     = length(var.public_subnet_cidrs) == 3 && alltrue([for cidr in var.public_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "public_subnet_cidrs must contain three valid IPv4 CIDRs."
  }
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "Three private ECS subnet CIDRs with no internet default route."
  validation {
    condition     = length(var.private_subnet_cidrs) == 3 && alltrue([for cidr in var.private_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "private_subnet_cidrs must contain three valid IPv4 CIDRs."
  }
}

variable "data_subnet_cidrs" {
  type        = list(string)
  description = "Three isolated managed-data subnet CIDRs."
  validation {
    condition     = length(var.data_subnet_cidrs) == 3 && alltrue([for cidr in var.data_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "data_subnet_cidrs must contain three valid IPv4 CIDRs."
  }
}

variable "application_hostname" {
  type        = string
  description = "Snowman-controlled public Command Center hostname."
  validation {
    condition     = can(regex("^[a-z0-9-]+(\\.[a-z0-9-]+)*\\.snowmanai\\.org$", var.application_hostname))
    error_message = "application_hostname must be a lowercase snowmanai.org subdomain."
  }
}

variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate for application_hostname in the workload account and region."
  validation {
    condition     = can(regex("^arn:aws[a-z-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-f-]+$", var.acm_certificate_arn))
    error_message = "acm_certificate_arn must be an ACM certificate ARN."
  }
}

variable "cloudflare_origin_ipv4_cidrs" {
  type        = set(string)
  description = "Reviewed Cloudflare IPv4 origin ranges; the ALB accepts no other public source."
  validation {
    condition     = length(var.cloudflare_origin_ipv4_cidrs) > 0 && alltrue([for cidr in var.cloudflare_origin_ipv4_cidrs : can(cidrnetmask(cidr))])
    error_message = "cloudflare_origin_ipv4_cidrs must contain valid reviewed IPv4 CIDRs."
  }
}

variable "database_instance_class" {
  type        = string
  description = "Cost-bounded RDS PostgreSQL instance class."
  default     = "db.t4g.small"
  validation {
    condition     = can(regex("^db\\.(t4g|m7g|r7g)\\.[a-z0-9]+$", var.database_instance_class))
    error_message = "database_instance_class must use an approved Graviton family."
  }
}

variable "database_engine_version" {
  type        = string
  description = "Pinned RDS PostgreSQL 17 minor version."
  default     = "17.5"
  validation {
    condition     = can(regex("^17\\.[0-9]+$", var.database_engine_version))
    error_message = "database_engine_version must pin a PostgreSQL 17 minor version."
  }
}

variable "database_allocated_storage_gib" {
  type        = number
  description = "Initial encrypted PostgreSQL gp3 storage."
  default     = 30
  validation {
    condition     = var.database_allocated_storage_gib >= 20 && var.database_allocated_storage_gib <= 1024
    error_message = "database_allocated_storage_gib must be between 20 and 1024."
  }
}

variable "database_max_storage_gib" {
  type        = number
  description = "Hard PostgreSQL autoscaling storage ceiling."
  default     = 100
  validation {
    condition     = var.database_max_storage_gib >= var.database_allocated_storage_gib && var.database_max_storage_gib <= 4096
    error_message = "database_max_storage_gib must be at least allocated storage and no more than 4096."
  }
}

variable "valkey_node_type" {
  type        = string
  description = "Cost-bounded managed Valkey node type."
  default     = "cache.t4g.small"
  validation {
    condition     = can(regex("^cache\\.(t4g|m7g|r7g)\\.[a-z0-9]+$", var.valkey_node_type))
    error_message = "valkey_node_type must use an approved Graviton family."
  }
}

variable "valkey_engine_version" {
  type        = string
  description = "Pinned managed Valkey major/minor version with IAM authentication support."
  default     = "8.0"
  validation {
    condition     = can(regex("^(7\\.[2-9]|8\\.[0-9]+)$", var.valkey_engine_version))
    error_message = "valkey_engine_version must be Valkey 7.2 or newer."
  }
}

variable "backup_retention_days" {
  type        = number
  description = "RDS and Valkey snapshot retention window."
  default     = 14
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 35
    error_message = "backup_retention_days must be between 7 and 35."
  }
}

variable "log_retention_days" {
  type        = number
  description = "Encrypted CloudWatch application and control log retention."
  default     = 365
  validation {
    condition     = contains([90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch-supported governed retention value of at least 90 days."
  }
}

variable "artifact_retention_days" {
  type        = number
  description = "Object-lock governance retention for command-center artifacts."
  default     = 365
  validation {
    condition     = var.artifact_retention_days >= 30 && var.artifact_retention_days <= 3650
    error_message = "artifact_retention_days must be between 30 and 3650."
  }
}

variable "media_noncurrent_retention_days" {
  type        = number
  description = "Retention for superseded/deleted command-center media versions."
  default     = 30
  validation {
    condition     = var.media_noncurrent_retention_days >= 7 && var.media_noncurrent_retention_days <= 365
    error_message = "media_noncurrent_retention_days must be between 7 and 365."
  }
}

variable "audit_retention_days" {
  type        = number
  description = "Object-lock compliance retention for signed audit checkpoints."
  default     = 2555
  validation {
    condition     = var.audit_retention_days >= 365 && var.audit_retention_days <= 3650
    error_message = "audit_retention_days must be between 365 and 3650."
  }
}

variable "deletion_protection" {
  type        = bool
  description = "Protect managed state from ordinary destroy operations."
  default     = true
}
