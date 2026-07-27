mock_provider "aws" {
  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "111111111111" }
  }
  override_data {
    target = data.aws_partition.current
    values = { partition = "aws" }
  }
  override_data {
    target = data.aws_region.current
    values = { name = "us-west-2" }
  }
  override_data {
    target = data.aws_iam_policy_document.logs_kms
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.object["artifacts"]
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.object["audit"]
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.media
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.operations_topic
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.ecs_task_trust
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.relay_execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.relay_task
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.workforce_execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.workforce_task
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.workforce_scheduler_execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.workforce_trigger_execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.workforce_reminder_execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.agent_executor_execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.agent_broker_execution
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

variables {
  aws_region                     = "us-west-2"
  environment                    = "staging"
  expected_workload_account_id   = "111111111111"
  management_account_id          = "222222222222"
  analyst360_workload_account_id = "333333333333"
  container_image                = "111111111111.dkr.ecr.us-west-2.amazonaws.com/snowman-command-center@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  monthly_budget_usd             = 250
  security_alert_email_endpoint  = "security@snowmanai.org"
  availability_zones             = ["us-west-2a", "us-west-2b", "us-west-2c"]
  public_subnet_cidrs            = ["10.72.0.0/24", "10.72.1.0/24", "10.72.2.0/24"]
  private_subnet_cidrs           = ["10.72.16.0/24", "10.72.17.0/24", "10.72.18.0/24"]
  data_subnet_cidrs              = ["10.72.32.0/24", "10.72.33.0/24", "10.72.34.0/24"]
  application_hostname           = "command.staging.snowmanai.org"
  acm_certificate_arn            = "arn:aws:acm:us-west-2:111111111111:certificate/00000000-0000-0000-0000-000000000000"
  cloudflare_origin_ipv4_cidrs   = ["192.0.2.0/24"]
}

run "dormant_staging_foundation" {
  command = plan

  assert {
    condition     = aws_db_instance.postgres.publicly_accessible == false
    error_message = "PostgreSQL must remain private."
  }
  assert {
    condition     = aws_db_instance.postgres.storage_encrypted
    error_message = "PostgreSQL must remain encrypted."
  }
  assert {
    condition     = aws_elasticache_replication_group.valkey.transit_encryption_enabled
    error_message = "Valkey must require TLS."
  }
  assert {
    condition     = aws_elasticache_user.relay.authentication_mode[0].type == "iam"
    error_message = "Valkey must use short-lived IAM authentication."
  }
  assert {
    condition     = length(aws_vpc_endpoint.interface) == 10
    error_message = "Every required private AWS service endpoint must exist."
  }
  assert {
    condition     = length(aws_vpc_endpoint.interface["kms"].subnet_ids) == 1
    error_message = "Dormant staging must use one cost-controlled interface endpoint ENI."
  }
  assert {
    condition     = aws_elasticache_replication_group.valkey.num_cache_clusters == 1
    error_message = "Dormant staging must use one cost-controlled Valkey node."
  }
  assert {
    condition     = aws_ecs_task_definition.relay.cpu == "512" && aws_ecs_task_definition.relay.memory == "1024"
    error_message = "The dormant relay task must keep its cost-bounded CPU and memory allocation."
  }
  assert {
    condition     = length(aws_lb.edge) == 0 && length(aws_wafv2_web_acl.edge) == 0
    error_message = "Dormant staging must not incur ALB/WAF edge cost."
  }
}

run "governed_workforce_bootstrap_manifest" {
  command = plan

  variables {
    workforce_community_id      = "10000000-0000-4000-8000-000000000001"
    workforce_community_host    = "aptive.staging.snowmanai.org"
    workforce_lead_identity_id  = "10000000-0000-4000-8000-000000000010"
    workforce_model_gateway_url = "https://models.staging.internal.snowmanai.org/v1"
    workforce_planning_model_id = "snowman-local-general-v1"
    workforce_private_hostnames = ["workforce.aptive.staging.snowmanai.org"]
    workforce_identity_authority = {
      broker_id                 = "snowman-analyst360-identity"
      provider                  = "google_workspace"
      hosted_domain             = "snowmanai.org"
      tenant_id                 = "aptive"
      client_id                 = "aptive"
      project_id                = "default"
      signing_kms_key_arn       = "arn:aws:kms:us-west-2:333333333333:key/00000000-0000-4000-8000-000000000030"
      max_session_seconds       = 900
      assurance_level           = "mfa"
      assurance_evidence_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      assurance_evaluated_at    = "2026-07-26T00:00:00Z"
    }
    workforce_model_routes = {
      snowman-local-general-v1 = {
        suited_roles                         = ["lead", "governed_analyst", "client_delivery", "quality_risk_reviewer", "deadline_operations"]
        allowed_classifications              = ["internal", "confidential", "restricted"]
        quality_score                        = 900
        latency_score                        = 700
        max_cost_microusd_per_million_tokens = 0
        max_context_tokens                   = 32768
        evaluation_evidence_sha256           = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        evaluated_at                         = "2026-07-26T00:00:00Z"
      }
    }
    workforce_profiles = {
      lead = {
        desired_count = 0, identity_id = "10000000-0000-4000-8000-000000000010", display_name = "Snowman Lead", specialist_role = "lead",
        relay_url     = "https://workforce.aptive.staging.snowmanai.org", analyst_endpoint = "https://analyst.aptive.staging.snowmanai.org", analyst_service_principal = "snowman-workforce-lead", analyst_signing_key_arn = "arn:aws:kms:us-west-2:333333333333:key/00000000-0000-4000-8000-000000000010", tenant_id = "aptive", client_id = "aptive", project_id = "default"
      }
      analyst = {
        desired_count = 0, identity_id = "10000000-0000-4000-8000-000000000011", display_name = "Snowman Governed Analyst", specialist_role = "governed_analyst",
        relay_url     = "https://workforce.aptive.staging.snowmanai.org", analyst_endpoint = "https://analyst.aptive.staging.snowmanai.org", analyst_service_principal = "snowman-workforce-analyst", analyst_signing_key_arn = "arn:aws:kms:us-west-2:333333333333:key/00000000-0000-4000-8000-000000000011", tenant_id = "aptive", client_id = "aptive", project_id = "default"
      }
      delivery = {
        desired_count = 0, identity_id = "10000000-0000-4000-8000-000000000012", display_name = "Snowman Client Delivery", specialist_role = "client_delivery",
        relay_url     = "https://workforce.aptive.staging.snowmanai.org", analyst_endpoint = "https://analyst.aptive.staging.snowmanai.org", analyst_service_principal = "snowman-workforce-delivery", analyst_signing_key_arn = "arn:aws:kms:us-west-2:333333333333:key/00000000-0000-4000-8000-000000000012", tenant_id = "aptive", client_id = "aptive", project_id = "default"
      }
      reviewer = {
        desired_count = 0, identity_id = "10000000-0000-4000-8000-000000000013", display_name = "Snowman Quality and Risk Reviewer", specialist_role = "quality_risk_reviewer",
        relay_url     = "https://workforce.aptive.staging.snowmanai.org", analyst_endpoint = "https://analyst.aptive.staging.snowmanai.org", analyst_service_principal = "snowman-workforce-reviewer", analyst_signing_key_arn = "arn:aws:kms:us-west-2:333333333333:key/00000000-0000-4000-8000-000000000013", tenant_id = "aptive", client_id = "aptive", project_id = "default"
      }
    }
    scheduler_profiles = {
      aptive = { desired_count = 0, identity_id = "10000000-0000-4000-8000-000000000020", relay_url = "https://workforce.aptive.staging.snowmanai.org" }
    }
    trigger_profiles = {
      aptive = { desired_count = 0, identity_id = "10000000-0000-4000-8000-000000000021", relay_url = "https://workforce.aptive.staging.snowmanai.org" }
    }
    reminder_profiles = {
      aptive = { desired_count = 0, identity_id = "10000000-0000-4000-8000-000000000022", relay_url = "https://workforce.aptive.staging.snowmanai.org" }
    }
  }

  assert {
    condition     = length(aws_secretsmanager_secret.workforce_identity) == 4 && length(local.workforce_identity_secret_arns) == 7
    error_message = "The governed team must create one exact secret container per service identity."
  }
  assert {
    condition     = local.workforce_team_identity_ids.lead == var.workforce_lead_identity_id && local.workforce_role_capabilities.quality_risk_reviewer == ["artifact.build", "artifact.review", "workforce.context.read", "workforce.context.write", "workforce.tasks.execute"]
    error_message = "Team identity and reviewer capabilities must remain exact."
  }
  assert {
    condition     = local.workforce_identity_authority_manifest.signing_kms_key_arn == var.workforce_identity_authority.signing_kms_key_arn
    error_message = "Bootstrap must bind the exact Snowman identity-authority KMS key."
  }
}

run "explicit_authenticated_edge" {
  command = plan

  variables {
    edge_enabled                     = true
    cloudflare_origin_pull_ca_pem    = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
    cloudflare_origin_pull_ca_sha256 = "57e5c4f97e96792b099ff6bfa1ad3fb9a08ed78ff734be7310ee4d02f71d1e16"
  }

  assert {
    condition     = length(aws_lb.edge) == 1 && !aws_lb.edge[0].internal && aws_lb.edge[0].enable_deletion_protection
    error_message = "Explicit edge activation must create one protected public ALB."
  }
  assert {
    condition     = aws_lb_listener.https[0].mutual_authentication[0].mode == "verify"
    error_message = "The public listener must verify the Cloudflare client certificate."
  }
  assert {
    condition     = aws_s3_object.origin_pull_ca[0].source_hash == var.cloudflare_origin_pull_ca_sha256
    error_message = "The trust-store object must match the reviewed CA digest."
  }
  assert {
    condition     = length(aws_wafv2_web_acl_association.edge) == 1
    error_message = "The edge ALB must have exactly one WAF association."
  }
}

run "credentialless_one_shot_agent_executor" {
  command = plan

  variables {
    agent_broker_url        = "https://agents.staging.internal.snowmanai.org:443/"
    agent_model_gateway_url = "https://models.staging.internal.snowmanai.org:443/"
    agent_runtime_profiles = {
      native-acp = {
        image                      = "111111111111.dkr.ecr.us-west-2.amazonaws.com/snowman-agent-runtime-native@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        runtime_id                 = "snowman-acp"
        cpu_architecture           = "ARM64"
        cpu                        = 1024
        memory                     = 4096
        ephemeral_storage_gib      = 30
        max_task_seconds           = 3600
        sbom_sha256                = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        provenance_sha256          = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        evaluation_evidence_sha256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      }
    }
  }

  assert {
    condition     = length(aws_ecs_task_definition.agent_executor) == 1
    error_message = "An evaluated profile must create exactly one dormant task definition."
  }
  assert {
    condition     = aws_ecs_task_definition.agent_executor["native-acp"].task_role_arn == null
    error_message = "The untrusted agent process must not receive an ECS task role."
  }
  assert {
    condition     = aws_ecs_task_definition.agent_executor["native-acp"].cpu == "1024" && aws_ecs_task_definition.agent_executor["native-acp"].memory == "4096"
    error_message = "The evaluated runtime profile must preserve its resource ceiling."
  }
}

run "private_dormant_agent_broker" {
  command = plan

  variables {
    agent_broker_url                     = "https://agents.staging.internal.snowmanai.org/"
    agent_broker_private_ingress_enabled = true
    agent_broker_private_dns_name        = "agents.staging.internal.snowmanai.org"
    agent_broker_tls_certificate_arn     = "arn:aws:acm:us-west-2:111111111111:certificate/10000000-0000-4000-8000-000000000001"
  }

  assert {
    condition     = length(aws_lb.agent_broker_private) == 1 && aws_lb.agent_broker_private[0].internal && aws_lb.agent_broker_private[0].enable_deletion_protection
    error_message = "The agent broker must use one protected internal load balancer."
  }
  assert {
    condition     = aws_lb_listener.agent_broker_private[0].protocol == "TLS" && aws_lb_listener.agent_broker_private[0].port == 443
    error_message = "The agent broker must expose only its private TLS listener."
  }
  assert {
    condition     = aws_lb_target_group.agent_broker_private[0].health_check[0].matcher == "200-299"
    error_message = "The broker readiness probe must accept its deliberate 204 response."
  }
  assert {
    condition     = aws_ecs_task_definition.agent_broker.task_role_arn == null && aws_ecs_service.agent_broker.desired_count == 0
    error_message = "The broker must remain dormant and receive no AWS task role."
  }
  assert {
    condition     = aws_route53_record.agent_broker_private[0].name == "agents.staging.internal.snowmanai.org"
    error_message = "The broker must use the exact split-horizon Snowman hostname."
  }
}

run "production_ha_foundation" {
  command = plan

  variables {
    environment           = "production"
    application_hostname  = "command.snowmanai.org"
    backup_retention_days = 35
  }

  assert {
    condition     = aws_db_instance.postgres.multi_az
    error_message = "Production PostgreSQL must be multi-AZ."
  }
  assert {
    condition     = aws_db_instance.postgres.backup_retention_period == 35
    error_message = "Production PostgreSQL must retain 35 days of PITR backups."
  }
  assert {
    condition     = aws_elasticache_replication_group.valkey.num_cache_clusters >= 2
    error_message = "Production Valkey must have a failover replica."
  }
  assert {
    condition     = aws_elasticache_replication_group.valkey.automatic_failover_enabled
    error_message = "Production Valkey automatic failover must be enabled."
  }
}
