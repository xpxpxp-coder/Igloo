output "production_boundary" {
  description = "Account, region, image, and activation coordinates reviewed by preflight."
  value = {
    account_id                            = data.aws_caller_identity.current.account_id
    region                                = data.aws_region.current.name
    environment                           = var.environment
    image                                 = var.container_image
    external_model_processors             = var.external_model_processors_enabled
    relay_desired_count                   = var.relay_desired_count
    worker_desired_count                  = var.worker_desired_count
    workforce_profile_count               = length(var.workforce_profiles)
    scheduler_desired_count               = var.scheduler_desired_count
    scheduler_profile_count               = length(var.scheduler_profiles)
    workforce_private_ingress_enabled     = var.workforce_private_ingress_enabled
    workforce_private_hostnames           = sort(tolist(var.workforce_private_hostnames))
    workforce_api_enabled                 = var.workforce_api_enabled
    workforce_worker_api_enabled          = var.workforce_worker_api_enabled
    analyst_event_api_enabled             = var.analyst_event_api_enabled
    model_gateway_desired_count           = var.model_gateway_desired_count
    model_gateway_private_ingress_enabled = var.model_gateway_private_ingress_enabled
  }
}

output "model_gateway_private_link" {
  description = "Cross-account private model-gateway handoff; the consumer must use the exact service name and verified Snowman private DNS identity."
  value = var.model_gateway_private_ingress_enabled ? {
    service_name                   = aws_vpc_endpoint_service.model_gateway[0].service_name
    service_id                     = aws_vpc_endpoint_service.model_gateway[0].id
    private_dns_name               = var.model_gateway_private_dns_name
    private_dns_verification_state = aws_vpc_endpoint_service.model_gateway[0].private_dns_name_configuration[0].state
    nlb_arn                        = aws_lb.model_gateway_private[0].arn
    tls_listener_arn               = aws_lb_listener.model_gateway_private[0].arn
    accepted_principals            = sort(tolist(var.model_gateway_consumer_principal_arns))
  } : null
}

output "network_posture" {
  description = "Isolated network coordinates for later dormant ECS services."
  value = {
    vpc_id                           = aws_vpc.command_center.id
    public_subnet_ids                = [for subnet in aws_subnet.public : subnet.id]
    private_subnet_ids               = [for subnet in aws_subnet.private : subnet.id]
    data_subnet_ids                  = [for subnet in aws_subnet.data : subnet.id]
    edge_security_group              = aws_security_group.edge.id
    relay_security_group             = aws_security_group.relay.id
    worker_security_group            = aws_security_group.worker.id
    scheduler_security_group         = aws_security_group.scheduler.id
    workforce_ingress_security_group = aws_security_group.workforce_ingress.id
    model_gateway_security_group     = aws_security_group.model_gateway.id
    inference_security_group         = aws_security_group.inference.id
    nat_gateway_count                = 0
    edge_enabled                     = var.edge_enabled
    edge_dns_name                    = var.edge_enabled ? aws_lb.edge[0].dns_name : null
    edge_zone_id                     = var.edge_enabled ? aws_lb.edge[0].zone_id : null
    edge_waf_log_group               = var.edge_enabled ? aws_cloudwatch_log_group.waf[0].name : null
  }
}

output "managed_state" {
  description = "Command Center-only managed-state coordinates; no Analyst 360 store is referenced."
  value = {
    postgres_endpoint     = aws_db_instance.postgres.address
    postgres_port         = aws_db_instance.postgres.port
    postgres_resource_id  = aws_db_instance.postgres.resource_id
    valkey_endpoint       = aws_elasticache_replication_group.valkey.primary_endpoint_address
    valkey_port           = aws_elasticache_replication_group.valkey.port
    valkey_iam_user_arn   = aws_elasticache_user.relay.arn
    object_bucket_arns    = merge({ for name, bucket in aws_s3_bucket.object : name => bucket.arn }, { media = aws_s3_bucket.media.arn })
    data_kms_key_arn      = aws_kms_key.data.arn
    audit_signing_key_arn = aws_kms_key.audit_checkpoint.arn
  }
}

output "valkey_runtime_contract" {
  description = "Non-secret relay settings and IAM resources required for short-lived Valkey authentication."
  value = {
    REDIS_URL                      = "rediss://${aws_elasticache_replication_group.valkey.primary_endpoint_address}:${aws_elasticache_replication_group.valkey.port}"
    SNOWMAN_VALKEY_IAM_ENABLED     = "true"
    SNOWMAN_VALKEY_IAM_USER_ID     = aws_elasticache_user.relay.user_id
    SNOWMAN_VALKEY_CACHE_NAME      = aws_elasticache_replication_group.valkey.replication_group_id
    AWS_REGION                     = data.aws_region.current.name
    required_iam_action            = "elasticache:Connect"
    required_replication_group_arn = aws_elasticache_replication_group.valkey.arn
    required_user_arn              = aws_elasticache_user.relay.arn
  }
}

output "operations_posture" {
  description = "Alert, budget, and logging coordinates requiring launch evidence."
  value = {
    ecs_cluster_arn      = aws_ecs_cluster.command_center.arn
    operations_topic_arn = aws_sns_topic.operations.arn
    budget_name          = aws_budgets_budget.monthly.name
    log_group_names      = { for name, group in aws_cloudwatch_log_group.runtime : name => group.name }
  }
}

output "dormant_compute_posture" {
  description = "Relay task and roles are defined but no service or desired runtime is activated."
  value = {
    bootstrap_task_definition_arn = aws_ecs_task_definition.bootstrap.arn
    bootstrap_execution_role_arn  = aws_iam_role.bootstrap_execution.arn
    bootstrap_task_role_arn       = aws_iam_role.bootstrap_task.arn
    relay_task_definition_arn     = aws_ecs_task_definition.relay.arn
    relay_execution_role_arn      = aws_iam_role.relay_execution.arn
    relay_task_role_arn           = aws_iam_role.relay_task.arn
    relay_runtime_secret_arn      = aws_secretsmanager_secret.relay_runtime.arn
    activated_service_count       = 0
  }
}
