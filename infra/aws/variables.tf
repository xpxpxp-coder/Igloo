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

variable "agent_runtime_profiles" {
  description = "Digest-pinned Snowman ACP runtime images eligible for one-shot agent sandbox tasks. Defining a profile creates no running compute."
  type = map(object({
    image                      = string
    runtime_id                 = string
    cpu_architecture           = string
    cpu                        = number
    memory                     = number
    ephemeral_storage_gib      = number
    max_task_seconds           = number
    sbom_sha256                = string
    provenance_sha256          = string
    evaluation_evidence_sha256 = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for name, profile in var.agent_runtime_profiles :
      can(regex("^[a-z][a-z0-9-]{2,31}$", name)) &&
      can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/snowman-agent-runtime-[a-z0-9-]+@sha256:[0-9a-f]{64}$", profile.image)) &&
      can(regex("^[a-z][a-z0-9-]{2,63}$", profile.runtime_id)) &&
      contains(["ARM64", "X86_64"], profile.cpu_architecture) &&
      contains([256, 512, 1024, 2048, 4096, 8192, 16384], profile.cpu) &&
      (
        (profile.cpu == 256 && contains([512, 1024, 2048], profile.memory)) ||
        (profile.cpu == 512 && profile.memory >= 1024 && profile.memory <= 4096 && profile.memory % 1024 == 0) ||
        (profile.cpu == 1024 && profile.memory >= 2048 && profile.memory <= 8192 && profile.memory % 1024 == 0) ||
        (profile.cpu == 2048 && profile.memory >= 4096 && profile.memory <= 16384 && profile.memory % 1024 == 0) ||
        (profile.cpu == 4096 && profile.memory >= 8192 && profile.memory <= 30720 && profile.memory % 1024 == 0) ||
        (profile.cpu == 8192 && profile.memory >= 16384 && profile.memory <= 61440 && profile.memory % 4096 == 0) ||
        (profile.cpu == 16384 && profile.memory >= 32768 && profile.memory <= 122880 && profile.memory % 8192 == 0)
      ) &&
      profile.ephemeral_storage_gib >= 21 && profile.ephemeral_storage_gib <= 200 &&
      profile.max_task_seconds >= 60 && profile.max_task_seconds <= 14400 &&
      can(regex("^[0-9a-f]{64}$", profile.sbom_sha256)) &&
      can(regex("^[0-9a-f]{64}$", profile.provenance_sha256)) &&
      can(regex("^[0-9a-f]{64}$", profile.evaluation_evidence_sha256))
    ])
    error_message = "Every agent runtime profile must be a bounded, digest-pinned Snowman ECR image with immutable supply-chain and evaluation evidence."
  }
}

variable "agent_broker_url" {
  type        = string
  description = "Private Snowman action-broker origin used by one-shot agent sandboxes."
  default     = ""
  validation {
    condition     = var.agent_broker_url == "" || (var.agent_broker_url == lower(var.agent_broker_url) && can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org(:443)?/?$", var.agent_broker_url)))
    error_message = "agent_broker_url must be empty or an exact lower-case Snowman HTTPS origin without a path."
  }
}

variable "agent_broker_desired_count" {
  type        = number
  description = "Desired private agent-broker tasks. The baseline remains dormant."
  default     = 0
  validation {
    condition     = var.agent_broker_desired_count >= 0 && var.agent_broker_desired_count <= 20
    error_message = "agent_broker_desired_count must be between 0 and 20."
  }
}

variable "agent_broker_private_ingress_enabled" {
  type        = bool
  description = "Create the cost-bearing internal TLS NLB and split-horizon DNS for the agent broker."
  default     = false
}

variable "agent_broker_tls_certificate_arn" {
  type        = string
  description = "Exact Command Center account ACM certificate for the private agent-broker hostname."
  default     = ""
  validation {
    condition = (
      !var.agent_broker_private_ingress_enabled ||
      can(regex("^arn:aws(?:-[a-z]+)?:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-fA-F-]{36}$", var.agent_broker_tls_certificate_arn))
    )
    error_message = "Private agent-broker ingress requires an exact ACM certificate ARN."
  }
}

variable "agent_broker_private_dns_name" {
  type        = string
  description = "Exact Snowman split-horizon hostname for the private agent broker."
  default     = ""
  validation {
    condition = (
      var.agent_broker_private_dns_name == "" ||
      can(regex("^agents(?:[.]staging)?[.]internal[.]snowmanai[.]org$", lower(var.agent_broker_private_dns_name)))
    )
    error_message = "agent_broker_private_dns_name must be empty or the exact staging or production Snowman private agent hostname."
  }
}

variable "agent_model_gateway_url" {
  type        = string
  description = "Private Snowman model-gateway origin used by one-shot agent sandboxes."
  default     = ""
  validation {
    condition     = var.agent_model_gateway_url == "" || (var.agent_model_gateway_url == lower(var.agent_model_gateway_url) && can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org(:443)?/?$", var.agent_model_gateway_url)))
    error_message = "agent_model_gateway_url must be empty or an exact lower-case Snowman HTTPS origin without a path."
  }
}

variable "scheduler_desired_count" {
  type        = number
  description = "Desired dedicated workforce maintenance scheduler tasks."
  default     = 0
  validation {
    condition     = var.scheduler_desired_count >= 0 && var.scheduler_desired_count <= 20
    error_message = "scheduler_desired_count must be between 0 and 20."
  }
}

variable "scheduler_profiles" {
  description = "Per-tenant maintenance scheduler identities. Secret values are populated out of band after creation."
  type = map(object({
    desired_count = number
    identity_id   = string
    relay_url     = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for name, profile in var.scheduler_profiles :
      can(regex("^[a-z][a-z0-9-]{2,19}$", name)) &&
      profile.desired_count >= 0 && profile.desired_count <= 1 &&
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", profile.identity_id)) &&
      can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org$", profile.relay_url))
    ])
    error_message = "Every scheduler profile must be a singleton, bounded Snowman HTTPS service identity."
  }
}

variable "trigger_desired_count" {
  type        = number
  description = "Desired dedicated recurring-work trigger tasks."
  default     = 0
  validation {
    condition     = var.trigger_desired_count >= 0 && var.trigger_desired_count <= 20
    error_message = "trigger_desired_count must be between 0 and 20."
  }
}

variable "trigger_profiles" {
  description = "Per-tenant recurring-work trigger identities. Secret values are populated out of band after creation."
  type = map(object({
    desired_count = number
    identity_id   = string
    relay_url     = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for name, profile in var.trigger_profiles :
      can(regex("^[a-z][a-z0-9-]{2,19}$", name)) &&
      profile.desired_count >= 0 && profile.desired_count <= 1 &&
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", profile.identity_id)) &&
      can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org$", profile.relay_url))
    ])
    error_message = "Every trigger profile must be a singleton, bounded Snowman HTTPS service identity."
  }
}

variable "reminder_desired_count" {
  type        = number
  description = "Desired dedicated Snowman-local reminder delivery tasks."
  default     = 0
  validation {
    condition     = var.reminder_desired_count >= 0 && var.reminder_desired_count <= 20
    error_message = "reminder_desired_count must be between 0 and 20."
  }
}

variable "reminder_profiles" {
  description = "Per-tenant reminder-only identities. Secret values are populated out of band after creation."
  type = map(object({
    desired_count = number
    identity_id   = string
    relay_url     = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for name, profile in var.reminder_profiles :
      can(regex("^[a-z][a-z0-9-]{2,19}$", name)) &&
      profile.desired_count >= 0 && profile.desired_count <= 1 &&
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", profile.identity_id)) &&
      can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org$", profile.relay_url))
    ])
    error_message = "Every reminder profile must be a singleton, bounded Snowman HTTPS service identity."
  }
}

variable "workforce_private_ingress_enabled" {
  type        = bool
  description = "Provision the internal Snowman TLS origin used only by workforce workers and schedulers."
  default     = false
}

variable "workforce_private_hostnames" {
  type        = set(string)
  description = "Exact tenant Snowman hostnames resolved privately to the workforce TLS origin."
  default     = []
  validation {
    condition = alltrue([
      for hostname in var.workforce_private_hostnames :
      can(regex("^([a-z0-9-]+\\.)*snowmanai\\.org$", hostname))
    ])
    error_message = "Private workforce hostnames must be exact lowercase Snowman domains."
  }
}

variable "workforce_api_enabled" {
  type        = bool
  description = "Enable the governed human workforce request API after identity and UAT gates pass."
  default     = false
}

variable "workforce_worker_api_enabled" {
  type        = bool
  description = "Enable private worker, scheduler, context, spend, and completion routes after runtime gates pass."
  default     = false
}

variable "workforce_lead_identity_id" {
  type        = string
  description = "Exact tenant-local lead service identity used when the workforce API is active."
  default     = ""
  validation {
    condition     = var.workforce_lead_identity_id == "" || can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.workforce_lead_identity_id))
    error_message = "workforce_lead_identity_id must be empty or a lowercase non-nil UUID."
  }
}

variable "workforce_community_id" {
  type        = string
  description = "Exact Command Center community receiving the governed service identities and model catalog."
  default     = ""
  validation {
    condition     = var.workforce_community_id == "" || can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", var.workforce_community_id))
    error_message = "workforce_community_id must be empty or a lowercase non-nil UUID."
  }
}

variable "workforce_community_host" {
  type        = string
  description = "Exact lower-case Snowman host bound to the governed workforce community."
  default     = ""
  validation {
    condition     = var.workforce_community_host == "" || can(regex("^(([a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])\\.)*snowmanai\\.org$", var.workforce_community_host))
    error_message = "workforce_community_host must be empty or an exact lower-case Snowman hostname."
  }
}

variable "workforce_model_gateway_url" {
  type        = string
  description = "Snowman-only model gateway used for governed workforce model selection."
  default     = ""
  validation {
    condition     = var.workforce_model_gateway_url == "" || (var.workforce_model_gateway_url == lower(var.workforce_model_gateway_url) && can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org(:443)?(/[^?#]*)?$", var.workforce_model_gateway_url)))
    error_message = "workforce_model_gateway_url must be empty or an exact Snowman HTTPS URL."
  }
}

variable "workforce_planning_model_id" {
  type        = string
  description = "Evaluated tenant model-catalog ID used by the lead planner."
  default     = ""
  validation {
    condition     = var.workforce_planning_model_id == "" || (length(var.workforce_planning_model_id) <= 256 && !strcontains(var.workforce_planning_model_id, "://"))
    error_message = "workforce_planning_model_id must be empty or a bounded catalog ID."
  }
}

variable "proactive_automatic_capabilities" {
  type        = set(string)
  description = "Explicit reversible capabilities eligible for server-side automatic execution. Empty is fail-closed."
  default     = []
  validation {
    condition = alltrue([
      for capability in var.proactive_automatic_capabilities :
      can(regex("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$", capability)) &&
      !contains(["admin.all", "aws.all", "filesystem.all", "network.all", "tool.all"], capability)
    ])
    error_message = "Automatic capabilities must be bounded namespaced grants and cannot be ambient authority."
  }
}

variable "proactive_max_automatic_cost_microusd" {
  type        = number
  description = "Hard per-action automatic execution ceiling in millionths of a US dollar."
  default     = 0
  validation {
    condition     = var.proactive_max_automatic_cost_microusd >= 0 && var.proactive_max_automatic_cost_microusd <= 500000000
    error_message = "proactive_max_automatic_cost_microusd must be between 0 and 500000000."
  }
}

variable "proactive_minimum_confidence_basis_points" {
  type        = number
  description = "Minimum usefulness confidence required for automatic execution."
  default     = 10000
  validation {
    condition     = var.proactive_minimum_confidence_basis_points >= 0 && var.proactive_minimum_confidence_basis_points <= 10000
    error_message = "proactive_minimum_confidence_basis_points must be between 0 and 10000."
  }
}

variable "analyst_event_api_enabled" {
  type        = bool
  description = "Enable the private Analyst 360 event receiver after KMS and cross-account routing gates pass."
  default     = false
}

variable "workforce_identity_api_enabled" {
  type        = bool
  description = "Enable the private KMS-authenticated Google Workspace human-session enrollment route."
  default     = false
}

variable "workforce_identity_authority" {
  description = "Exact Snowman identity authority, tenant scope, signing key, session ceiling, and reviewed Workspace MFA evidence."
  type = object({
    broker_id                 = string
    provider                  = string
    hosted_domain             = string
    tenant_id                 = string
    client_id                 = string
    project_id                = string
    signing_kms_key_arn       = string
    max_session_seconds       = number
    assurance_level           = string
    assurance_evidence_sha256 = string
    assurance_evaluated_at    = string
  })
  default  = null
  nullable = true
  validation {
    condition = try(var.workforce_identity_authority == null || (
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$", var.workforce_identity_authority.broker_id)) &&
      var.workforce_identity_authority.provider == "google_workspace" &&
      (
        var.workforce_identity_authority.hosted_domain == "snowmanai.org" ||
        can(regex("^[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.snowmanai\\.org$", var.workforce_identity_authority.hosted_domain))
      ) &&
      var.workforce_identity_authority.tenant_id == var.workforce_identity_authority.client_id &&
      alltrue([for value in [var.workforce_identity_authority.tenant_id, var.workforce_identity_authority.client_id, var.workforce_identity_authority.project_id] : can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$", value))]) &&
      can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$", var.workforce_identity_authority.signing_kms_key_arn)) &&
      var.workforce_identity_authority.max_session_seconds >= 60 && var.workforce_identity_authority.max_session_seconds <= 3600 &&
      contains(["mfa", "phishing_resistant"], var.workforce_identity_authority.assurance_level) &&
      can(regex("^[0-9a-f]{64}$", var.workforce_identity_authority.assurance_evidence_sha256)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", var.workforce_identity_authority.assurance_evaluated_at))
    ), false)
    error_message = "The workforce identity authority must be an exact Snowman Google/KMS binding with tenant-consistent scope and reviewed MFA evidence."
  }
}

variable "workforce_profiles" {
  description = "Per-identity durable workforce definitions. Secret values are populated out of band after creation."
  type = map(object({
    desired_count             = number
    identity_id               = string
    display_name              = string
    specialist_role           = string
    model_override            = optional(string)
    relay_url                 = string
    analyst_endpoint          = string
    analyst_service_principal = string
    analyst_signing_key_arn   = string
    tenant_id                 = string
    client_id                 = string
    project_id                = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for name, profile in var.workforce_profiles :
      can(regex("^[a-z][a-z0-9-]{2,19}$", name)) &&
      profile.desired_count >= 0 && profile.desired_count <= 20 &&
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", profile.identity_id)) &&
      length(trimspace(profile.display_name)) >= 1 && length(profile.display_name) <= 256 &&
      contains(["lead", "governed_analyst", "client_delivery", "quality_risk_reviewer", "research_evidence"], profile.specialist_role) &&
      (profile.model_override == null || (length(profile.model_override) >= 1 && length(profile.model_override) <= 256 && !strcontains(profile.model_override, "://"))) &&
      can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org$", profile.relay_url)) &&
      can(regex("^https://([a-z0-9-]+\\.)*snowmanai\\.org$", profile.analyst_endpoint)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$", profile.analyst_service_principal)) &&
      can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$", profile.analyst_signing_key_arn)) &&
      profile.tenant_id == profile.client_id
    ])
    error_message = "Every workforce profile must be a bounded, tenant-consistent Snowman HTTPS identity definition."
  }
}

variable "workforce_model_routes" {
  description = "Evaluated tenant model catalog. Map keys are model IDs; all traffic stays behind the Snowman model gateway."
  type = map(object({
    suited_roles                         = set(string)
    allowed_classifications              = set(string)
    quality_score                        = number
    latency_score                        = number
    max_cost_microusd_per_million_tokens = number
    max_context_tokens                   = number
    evaluation_evidence_sha256           = string
    evaluated_at                         = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for model_id, route in var.workforce_model_routes :
      length(model_id) >= 1 && length(model_id) <= 256 && !strcontains(model_id, "://") &&
      length(route.suited_roles) >= 1 && length(route.suited_roles) <= 16 &&
      alltrue([for role in route.suited_roles : contains(["lead", "client_delivery", "research_evidence", "governed_analyst", "quality_risk_reviewer", "deadline_operations"], role)]) &&
      length(route.allowed_classifications) >= 1 && length(route.allowed_classifications) <= 3 &&
      alltrue([for value in route.allowed_classifications : contains(["internal", "confidential", "restricted"], value)]) &&
      route.quality_score >= 0 && route.quality_score <= 1000 &&
      route.latency_score >= 0 && route.latency_score <= 1000 &&
      route.max_cost_microusd_per_million_tokens >= 0 &&
      route.max_context_tokens >= 1 && route.max_context_tokens <= 10000000 &&
      can(regex("^[0-9a-f]{64}$", route.evaluation_evidence_sha256)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", route.evaluated_at))
    ])
    error_message = "Every workforce model route must have a bounded ID, roles, classifications, scores, cost/context limits, evidence digest, and RFC3339 evaluation time."
  }
}

variable "analyst360_private_prefix_list_id" {
  type        = string
  description = "Cross-account private Analyst 360 endpoint prefix list. Required only when workforce tasks activate."
  default     = ""
  validation {
    condition     = var.analyst360_private_prefix_list_id == "" || can(regex("^pl-[0-9a-f]+$", var.analyst360_private_prefix_list_id))
    error_message = "analyst360_private_prefix_list_id must be empty or an AWS managed prefix-list ID."
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

variable "model_gateway_private_ingress_enabled" {
  type        = bool
  description = "Create the internal TLS NLB and cross-account PrivateLink endpoint service for the model gateway."
  default     = false
}

variable "model_gateway_tls_certificate_arn" {
  type        = string
  description = "Exact Command Center account ACM certificate for the private model-gateway hostname."
  default     = ""
  validation {
    condition = (
      !var.model_gateway_private_ingress_enabled ||
      can(regex("^arn:aws(?:-[a-z]+)?:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-fA-F-]{36}$", var.model_gateway_tls_certificate_arn))
    )
    error_message = "Private model-gateway ingress requires an exact ACM certificate ARN."
  }
}

variable "model_gateway_private_dns_name" {
  type        = string
  description = "Snowman-owned private DNS identity advertised by the endpoint service."
  default     = "models.internal.snowmanai.org"
  validation {
    condition     = can(regex("^models(?:[.]staging)?[.]internal[.]snowmanai[.]org$", lower(var.model_gateway_private_dns_name)))
    error_message = "model_gateway_private_dns_name must be the exact staging or production Snowman private model hostname."
  }
}

variable "model_gateway_consumer_principal_arns" {
  type        = set(string)
  description = "Exact Analyst workload IAM principals allowed to create a model-gateway interface endpoint."
  default     = []
  validation {
    condition = alltrue([
      for arn in var.model_gateway_consumer_principal_arns :
      can(regex("^arn:aws(?:-[a-z]+)?:iam::[0-9]{12}:(?:root|role/[A-Za-z0-9+=,.@_/-]{1,512})$", arn))
    ])
    error_message = "Every model-gateway consumer must be an exact AWS account-root or role principal ARN."
  }
}

variable "model_gateway_principals" {
  description = "Analyst workload policies allowed to call the private model gateway. Map keys are exact service principal IDs."
  type = map(object({
    key_id           = string
    tenant_id        = string
    client_id        = string
    project_id       = string
    model_ids        = set(string)
    specialist_roles = set(string)
    capabilities     = set(string)
    classifications  = set(string)
  }))
  default = {}
  validation {
    condition = alltrue([
      for principal_id, policy in var.model_gateway_principals :
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$", principal_id)) &&
      can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$", policy.key_id)) &&
      policy.tenant_id == policy.client_id &&
      length(policy.model_ids) > 0 && length(policy.specialist_roles) > 0 &&
      length(policy.capabilities) > 0 && length(policy.classifications) > 0 &&
      alltrue([for classification in policy.classifications : contains(["internal", "confidential", "restricted"], classification)])
    ])
    error_message = "Every model-gateway principal must be a non-empty, tenant-consistent, KMS-bound policy."
  }
}

variable "model_gateway_routes" {
  description = "Operations-owned model catalog. Map keys are public Snowman model IDs; each backend is a private Snowman origin or an exact same-account SageMaker endpoint."
  type = map(object({
    backend_kind                       = string
    backend_origin                     = optional(string)
    sagemaker_endpoint_name            = optional(string)
    sagemaker_inference_component_name = optional(string)
    backend_model                      = string
    max_input_tokens                   = number
    max_output_tokens                  = number
    max_cost_microusd                  = number
    input_microusd_per_million_tokens  = number
    output_microusd_per_million_tokens = number
  }))
  default = {}
  validation {
    condition = alltrue([
      for model_id, route in var.model_gateway_routes :
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$", model_id)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$", route.backend_model)) &&
      contains(["private_openai", "sagemaker"], route.backend_kind) &&
      (
        (route.backend_kind == "private_openai" && route.sagemaker_endpoint_name == null && route.sagemaker_inference_component_name == null && (
          can(regex("^http://[a-z0-9-]+([.][a-z0-9-]+)*[.](internal|local):[0-9]{2,5}$", route.backend_origin)) ||
          can(regex("^https://([a-z0-9-]+[.])*snowmanai[.]org$", route.backend_origin))
        )) ||
        (route.backend_kind == "sagemaker" && route.backend_origin == null &&
          can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", route.sagemaker_endpoint_name)) &&
        can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", route.sagemaker_inference_component_name)))
      ) &&
      route.max_input_tokens > 0 && route.max_input_tokens <= 1000000 &&
      route.max_output_tokens > 0 && route.max_output_tokens <= 100000 &&
      route.max_cost_microusd > 0 && route.max_cost_microusd <= 100000000 &&
      route.input_microusd_per_million_tokens >= 0 &&
      route.output_microusd_per_million_tokens >= 0
    ])
    error_message = "Every model route must bind a bounded Snowman model ID to exactly one private runtime or same-account SageMaker endpoint."
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

variable "edge_enabled" {
  type        = bool
  description = "Create the cost-bearing Cloudflare-authenticated ALB/WAF edge. Dormant baselines keep this false."
  default     = false
}

variable "cloudflare_origin_pull_ca_pem" {
  type        = string
  description = "Public CA bundle for the Snowman-specific Cloudflare authenticated-origin-pull client certificate."
  default     = ""
  sensitive   = true
  validation {
    condition = (
      !var.edge_enabled ||
      (startswith(trimspace(var.cloudflare_origin_pull_ca_pem), "-----BEGIN CERTIFICATE-----") &&
      endswith(trimspace(var.cloudflare_origin_pull_ca_pem), "-----END CERTIFICATE-----"))
    )
    error_message = "An enabled edge requires a PEM Cloudflare origin-pull CA bundle."
  }
}

variable "cloudflare_origin_pull_ca_sha256" {
  type        = string
  description = "Reviewed lowercase SHA-256 digest of the exact public origin-pull CA PEM."
  default     = ""
  validation {
    condition     = !var.edge_enabled || can(regex("^[0-9a-f]{64}$", var.cloudflare_origin_pull_ca_sha256))
    error_message = "An enabled edge requires a reviewed lowercase SHA-256 CA digest."
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
