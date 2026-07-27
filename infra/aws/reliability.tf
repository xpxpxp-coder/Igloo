locals {
  runtime_error_metrics = {
    for service in local.runtime_log_groups : service => replace(service, "-", "_")
  }
}

resource "aws_cloudwatch_log_metric_filter" "runtime_error" {
  for_each = local.runtime_error_metrics

  name           = "${local.workload_name}-${each.key}-errors"
  log_group_name = aws_cloudwatch_log_group.runtime[each.key].name
  pattern        = "{ $.level = \"ERROR\" }"

  metric_transformation {
    name          = "${each.value}_errors"
    namespace     = "Snowman/CommandCenter"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "runtime_error" {
  for_each = local.runtime_error_metrics

  alarm_name          = "${local.workload_name}-${each.key}-errors"
  alarm_description   = "Snowman Command Center ${each.key} emitted an error; alert content contains no tenant payload."
  namespace           = "Snowman/CommandCenter"
  metric_name         = "${each.value}_errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.runtime_error]
}

resource "aws_cloudwatch_dashboard" "operations" {
  dashboard_name = "${local.workload_name}-operations"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = "# Snowman Command Center — ${var.environment}\nControl metadata only. Tenant names, prompts, messages, transcripts, artifact bodies, credentials, and raw client data are prohibited from metrics and alert payloads."
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 2
        width  = 12
        height = 6
        properties = {
          title  = "Managed PostgreSQL"
          region = var.aws_region
          period = 300
          stat   = "Average"
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.postgres.identifier],
            [".", "FreeStorageSpace", ".", "."],
            [".", "FreeableMemory", ".", "."],
            [".", "DatabaseConnections", ".", "."],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 2
        width  = 12
        height = 6
        properties = {
          title  = "Managed Valkey"
          region = var.aws_region
          period = 300
          stat   = "Average"
          metrics = [
            ["AWS/ElastiCache", "EngineCPUUtilization", "ReplicationGroupId", aws_elasticache_replication_group.valkey.replication_group_id],
            [".", "FreeableMemory", ".", "."],
            [".", "CurrConnections", ".", "."],
            [".", "Evictions", ".", ".", { stat = "Sum" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 24
        height = 8
        properties = {
          title  = "Redacted runtime errors by Snowman service"
          region = var.aws_region
          period = 300
          stat   = "Sum"
          metrics = [
            for service, metric in local.runtime_error_metrics :
            ["Snowman/CommandCenter", "${metric}_errors", { label = service }]
          ]
        }
      },
    ]
  })
}
