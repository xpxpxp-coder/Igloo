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
    condition     = length(aws_vpc_endpoint.interface) == 8
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
