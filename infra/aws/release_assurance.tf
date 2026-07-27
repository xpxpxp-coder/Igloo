check "encrypted_backup_and_pitr_posture" {
  assert {
    condition = (
      aws_db_instance.postgres.storage_encrypted &&
      aws_db_instance.postgres.kms_key_id == aws_kms_key.data.arn &&
      aws_db_instance.postgres.iam_database_authentication_enabled &&
      aws_db_instance.postgres.backup_retention_period == var.backup_retention_days &&
      aws_db_instance.postgres.delete_automated_backups == false &&
      aws_db_instance.postgres.skip_final_snapshot == false &&
      aws_db_instance.postgres.deletion_protection &&
      aws_elasticache_replication_group.valkey.at_rest_encryption_enabled &&
      aws_elasticache_replication_group.valkey.transit_encryption_enabled &&
      aws_elasticache_replication_group.valkey.kms_key_id == aws_kms_key.data.arn &&
      aws_elasticache_replication_group.valkey.snapshot_retention_limit == var.backup_retention_days &&
      aws_s3_bucket.object["audit"].object_lock_enabled &&
      aws_s3_bucket_versioning.object["audit"].versioning_configuration[0].status == "Enabled" &&
      aws_s3_bucket_object_lock_configuration.object["audit"].rule[0].default_retention[0].mode == "COMPLIANCE"
    )
    error_message = "Launch evidence requires encrypted RDS PITR, retained Valkey snapshots, retained final database snapshots, and versioned COMPLIANCE-locked audit evidence."
  }
}

locals {
  hard_dormant_service_names = {
    meeting-command   = aws_ecs_service.meeting_command.name
    orchestration-api = aws_ecs_service.orchestration_api.name
  }
}

resource "aws_cloudwatch_metric_alarm" "hard_dormant_service_started" {
  for_each = local.hard_dormant_service_names

  alarm_name          = "${local.workload_name}-${each.key}-unexpected-running"
  alarm_description   = "A hard-dormant Snowman service started outside a reviewed staging verification window."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.command_center.name
    ServiceName = each.value
  }
}

resource "aws_cloudwatch_metric_alarm" "hard_dormant_orchestration_worker_started" {
  for_each = aws_ecs_service.orchestration_worker

  alarm_name          = "${local.workload_name}-orchestration-worker-${each.key}-unexpected-running"
  alarm_description   = "A hard-dormant orchestration worker started outside a reviewed staging verification window."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.command_center.name
    ServiceName = each.value.name
  }
}

resource "aws_cloudwatch_metric_alarm" "hard_dormant_meeting_media_started" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  alarm_name          = "${local.workload_name}-meeting-media-unexpected-running"
  alarm_description   = "The hard-dormant meeting-media gateway started outside a reviewed staging verification window."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.command_center.name
    ServiceName = aws_ecs_service.meeting_media[0].name
  }
}

resource "aws_cloudwatch_metric_alarm" "hard_dormant_provider_egress_started" {
  count = local.provider_egress_packaged ? 1 : 0

  alarm_name          = "${local.workload_name}-provider-egress-unexpected-running"
  alarm_description   = "The hard-dormant provider-egress proxy started outside a reviewed staging verification window."
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.command_center.name
    ServiceName = aws_ecs_service.provider_egress[0].name
  }
}

output "release_assurance_posture" {
  description = "Digest-free backup, dormancy, and cost-control posture; live reports remain version-bound launch evidence."
  value = {
    rds_storage_encrypted            = aws_db_instance.postgres.storage_encrypted
    rds_pitr_retention_days          = aws_db_instance.postgres.backup_retention_period
    rds_automated_backups_preserved  = !aws_db_instance.postgres.delete_automated_backups
    rds_final_snapshot_required      = !aws_db_instance.postgres.skip_final_snapshot
    valkey_storage_encrypted         = aws_elasticache_replication_group.valkey.at_rest_encryption_enabled
    valkey_snapshot_retention_days   = aws_elasticache_replication_group.valkey.snapshot_retention_limit
    audit_evidence_object_lock       = aws_s3_bucket.object["audit"].object_lock_enabled
    audit_evidence_retention_mode    = aws_s3_bucket_object_lock_configuration.object["audit"].rule[0].default_retention[0].mode
    unexpected_runtime_alarm_count   = length(local.hard_dormant_service_names) + length(aws_ecs_service.orchestration_worker) + (local.meeting_media_runtime_packaged ? 1 : 0) + (local.provider_egress_packaged ? 1 : 0)
    monthly_budget_name              = aws_budgets_budget.monthly.name
    activation_evidence_required     = true
    migration_restore_rehearsal_live = false
    backup_restore_rehearsal_live    = false
  }
}
