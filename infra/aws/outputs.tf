output "production_boundary" {
  description = "Account, region, image, and activation coordinates reviewed by preflight."
  value = {
    account_id                  = data.aws_caller_identity.current.account_id
    region                      = data.aws_region.current.name
    environment                 = var.environment
    image                       = var.container_image
    external_model_processors   = var.external_model_processors_enabled
    relay_desired_count         = var.relay_desired_count
    worker_desired_count        = var.worker_desired_count
    model_gateway_desired_count = var.model_gateway_desired_count
  }
}

output "network_posture" {
  description = "Isolated network coordinates for later dormant ECS services."
  value = {
    vpc_id                       = aws_vpc.command_center.id
    public_subnet_ids            = [for subnet in aws_subnet.public : subnet.id]
    private_subnet_ids           = [for subnet in aws_subnet.private : subnet.id]
    data_subnet_ids              = [for subnet in aws_subnet.data : subnet.id]
    edge_security_group          = aws_security_group.edge.id
    relay_security_group         = aws_security_group.relay.id
    worker_security_group        = aws_security_group.worker.id
    model_gateway_security_group = aws_security_group.model_gateway.id
    inference_security_group     = aws_security_group.inference.id
    nat_gateway_count            = 0
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

output "operations_posture" {
  description = "Alert, budget, and logging coordinates requiring launch evidence."
  value = {
    ecs_cluster_arn      = aws_ecs_cluster.command_center.arn
    operations_topic_arn = aws_sns_topic.operations.arn
    budget_name          = aws_budgets_budget.monthly.name
    log_group_names      = { for name, group in aws_cloudwatch_log_group.runtime : name => group.name }
  }
}
