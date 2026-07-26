locals {
  runtime_log_groups = toset([
    "relay",
    "workforce-worker",
    "workforce-scheduler",
    "workforce-trigger",
    "model-gateway",
    "inference",
    "migration",
    "audit-checkpoint",
  ])
}

resource "aws_cloudwatch_log_group" "runtime" {
  for_each = local.runtime_log_groups

  name              = "/snowman/command-center/${var.environment}/${each.value}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_ecs_cluster" "command_center" {
  name = local.workload_name

  setting {
    name  = "containerInsights"
    value = "enhanced"
  }

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.logs.arn
      logging    = "OVERRIDE"
      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.runtime["audit-checkpoint"].name
      }
    }
  }
}

resource "aws_sns_topic" "operations" {
  name              = "${local.workload_name}-operations"
  kms_master_key_id = aws_kms_key.logs.arn
}

data "aws_iam_policy_document" "operations_topic" {
  statement {
    sid    = "AccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.expected_workload_account_id}:root"]
    }
    actions   = ["sns:*"]
    resources = [aws_sns_topic.operations.arn]
  }

  statement {
    sid    = "AwsControlPlanePublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com", "cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.operations.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.expected_workload_account_id]
    }
  }
}

resource "aws_sns_topic_policy" "operations" {
  arn    = aws_sns_topic.operations.arn
  policy = data.aws_iam_policy_document.operations_topic.json
}

resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.operations.arn
  protocol  = "email"
  endpoint  = var.security_alert_email_endpoint
}

resource "aws_budgets_budget" "monthly" {
  name         = "${local.workload_name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Application$snowman-command-center"]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_sns_topic_arns = [aws_sns_topic.operations.arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.operations.arn]
  }
}

resource "aws_cloudwatch_metric_alarm" "postgres_cpu" {
  alarm_name          = "${local.workload_name}-postgres-cpu"
  alarm_description   = "Sustained Command Center PostgreSQL CPU saturation"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions          = { DBInstanceIdentifier = aws_db_instance.postgres.identifier }
}

resource "aws_cloudwatch_metric_alarm" "postgres_storage" {
  alarm_name          = "${local.workload_name}-postgres-storage"
  alarm_description   = "Command Center PostgreSQL free storage below 10 GiB"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 10737418240
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions          = { DBInstanceIdentifier = aws_db_instance.postgres.identifier }
}

resource "aws_cloudwatch_metric_alarm" "valkey_cpu" {
  alarm_name          = "${local.workload_name}-valkey-cpu"
  alarm_description   = "Sustained Command Center Valkey engine CPU saturation"
  namespace           = "AWS/ElastiCache"
  metric_name         = "EngineCPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions          = { ReplicationGroupId = aws_elasticache_replication_group.valkey.replication_group_id }
}

resource "aws_cloudwatch_metric_alarm" "valkey_evictions" {
  alarm_name          = "${local.workload_name}-valkey-evictions"
  alarm_description   = "Command Center Valkey evicted data"
  namespace           = "AWS/ElastiCache"
  metric_name         = "Evictions"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions          = { ReplicationGroupId = aws_elasticache_replication_group.valkey.replication_group_id }
}
