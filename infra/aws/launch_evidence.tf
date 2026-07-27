variable "staging_verification_window_enabled" {
  type        = bool
  description = "Explicitly open a bounded staging verification window after immutable launch evidence exists."
  default     = false
}

variable "production_activation_enabled" {
  type        = bool
  description = "Final sole-founder production acceptance switch. It is insufficient without current immutable launch evidence."
  default     = false
}

variable "launch_evidence" {
  description = "Digest-only binding to a current, immutable Snowman launch-evidence manifest. Never place report bodies or secrets in Terraform."
  type = object({
    manifest_sha256                = string
    source_commit_sha              = string
    container_image                = string
    sbom_sha256                    = string
    provenance_sha256              = string
    signature_bundle_sha256        = string
    vulnerability_report_sha256    = string
    tenant_isolation_report_sha256 = string
    restore_report_sha256          = string
    audit_checkpoint_report_sha256 = string
    telemetry_report_sha256        = string
    alert_delivery_report_sha256   = string
    rollback_report_sha256         = string
    cost_report_sha256             = string
    terraform_plan_sha256          = string
    operator_acceptance_sha256     = optional(string)
    generated_at                   = string
    expires_at                     = string
    immutable_manifest_uri         = string
    alert_subscription_confirmed   = bool
    unresolved_critical_findings   = number
    unresolved_high_findings       = number
  })
  default  = null
  nullable = true
}

locals {
  runtime_activation_requested = (
    var.relay_desired_count > 0 ||
    var.worker_desired_count > 0 ||
    var.scheduler_desired_count > 0 ||
    var.trigger_desired_count > 0 ||
    var.reminder_desired_count > 0 ||
    var.agent_broker_desired_count > 0 ||
    var.agent_coordinator_desired_count > 0 ||
    var.model_gateway_desired_count > 0 ||
    var.workforce_api_enabled ||
    var.workforce_worker_api_enabled ||
    var.workforce_identity_api_enabled ||
    var.analyst_event_api_enabled
  )

  launch_evidence_digest_fields = var.launch_evidence == null ? [] : [
    var.launch_evidence.manifest_sha256,
    var.launch_evidence.sbom_sha256,
    var.launch_evidence.provenance_sha256,
    var.launch_evidence.signature_bundle_sha256,
    var.launch_evidence.vulnerability_report_sha256,
    var.launch_evidence.tenant_isolation_report_sha256,
    var.launch_evidence.restore_report_sha256,
    var.launch_evidence.audit_checkpoint_report_sha256,
    var.launch_evidence.telemetry_report_sha256,
    var.launch_evidence.alert_delivery_report_sha256,
    var.launch_evidence.rollback_report_sha256,
    var.launch_evidence.cost_report_sha256,
    var.launch_evidence.terraform_plan_sha256,
  ]

  launch_evidence_valid = var.launch_evidence != null && alltrue([
    can(regex("^[0-9a-f]{40}$", try(var.launch_evidence.source_commit_sha, ""))),
    alltrue([for digest in local.launch_evidence_digest_fields : can(regex("^[0-9a-f]{64}$", digest))]),
    try(var.launch_evidence.container_image, "") == var.container_image,
    try(var.launch_evidence.alert_subscription_confirmed, false),
    try(var.launch_evidence.unresolved_critical_findings, -1) == 0,
    try(var.launch_evidence.unresolved_high_findings, -1) == 0,
    can(timecmp(try(var.launch_evidence.generated_at, ""), plantimestamp())),
    can(timecmp(try(var.launch_evidence.expires_at, ""), plantimestamp())),
    try(timecmp(var.launch_evidence.generated_at, plantimestamp()), 1) <= 0,
    try(timecmp(var.launch_evidence.generated_at, timeadd(plantimestamp(), "-744h")), -1) >= 0,
    try(timecmp(var.launch_evidence.expires_at, plantimestamp()), -1) > 0,
    try(timecmp(var.launch_evidence.expires_at, timeadd(var.launch_evidence.generated_at, "744h")), 1) <= 0,
    can(regex(
      "^s3://snowman-cc-${var.environment}-audit-[a-z0-9-]+/.+[?&]versionId=[A-Za-z0-9+/=_-]{1,1024}$",
      try(var.launch_evidence.immutable_manifest_uri, "")
    )),
    var.environment != "production" || can(regex(
      "^[0-9a-f]{64}$",
      try(var.launch_evidence.operator_acceptance_sha256, "")
    )),
  ])

  activation_mode_authorized = (
    (var.environment == "staging" && var.staging_verification_window_enabled && !var.production_activation_enabled) ||
    (var.environment == "production" && var.production_activation_enabled && !var.staging_verification_window_enabled)
  )
}

resource "terraform_data" "launch_evidence_preflight" {
  input = {
    activation_requested = local.runtime_activation_requested
    environment          = var.environment
    evidence_digest      = try(var.launch_evidence.manifest_sha256, null)
    evidence_expires_at  = try(var.launch_evidence.expires_at, null)
    image                = var.container_image
  }

  lifecycle {
    precondition {
      condition     = !local.runtime_activation_requested || local.activation_mode_authorized
      error_message = "Runtime activation requires exactly one environment-appropriate staging-verification or production-activation switch."
    }

    precondition {
      condition     = !local.runtime_activation_requested || local.launch_evidence_valid
      error_message = "Runtime activation requires current immutable Snowman launch evidence bound to this exact image, with restore, audit, telemetry, alarm, rollback, cost, isolation, supply-chain, vulnerability, and final-acceptance proof."
    }

    precondition {
      condition     = var.environment == "staging" || !var.staging_verification_window_enabled
      error_message = "The staging verification switch cannot be used in production."
    }

    precondition {
      condition     = var.environment == "production" || !var.production_activation_enabled
      error_message = "The production activation switch cannot be used in staging."
    }
  }
}
