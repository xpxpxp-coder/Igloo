locals {
  audit_checkpoint_build_sha256 = try(regex("@sha256:([0-9a-f]{64})$", var.container_image)[0], "")
  audit_checkpoint_ready = (
    var.audit_checkpoint_database_schema_sha256 != "" &&
    local.audit_checkpoint_build_sha256 != ""
  )
}

check "audit_checkpoint_activation" {
  assert {
    condition     = !var.audit_checkpoint_schedule_enabled || local.audit_checkpoint_ready
    error_message = "The checkpoint schedule requires exact image and database-schema digests."
  }
}

data "aws_iam_policy_document" "audit_checkpoint_execution" {
  statement {
    sid       = "EcrAuthorization"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid    = "ExactImageRepository"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:ecr:${var.aws_region}:${var.expected_workload_account_id}:repository/snowman-command-center"]
  }
  statement {
    sid       = "CheckpointLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["audit-checkpoint"].arn}:*"]
  }
  statement {
    sid       = "ExactRuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.audit_checkpoint_runtime.arn]
  }
  statement {
    sid       = "RuntimeSecretKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "audit_checkpoint_execution" {
  name               = "${local.workload_name}-audit-checkpoint-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

resource "aws_iam_role_policy" "audit_checkpoint_execution" {
  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.audit_checkpoint_execution.id
  policy = data.aws_iam_policy_document.audit_checkpoint_execution.json
}

data "aws_iam_policy_document" "audit_checkpoint_task" {
  statement {
    sid       = "ListImmutableCheckpointVersions"
    effect    = "Allow"
    actions   = ["s3:ListBucketVersions"]
    resources = [aws_s3_bucket.object["audit"].arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["checkpoints/*"]
    }
  }
  statement {
    sid       = "ReadAndCreateCheckpointObjectsOnly"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"]
    resources = ["${aws_s3_bucket.object["audit"].arn}/checkpoints/*"]
  }
  statement {
    sid       = "SignAndVerifyCheckpointDigest"
    effect    = "Allow"
    actions   = ["kms:Sign", "kms:Verify", "kms:GetPublicKey"]
    resources = [aws_kms_key.audit_checkpoint.arn]
  }
  statement {
    sid    = "CheckpointEncryptionOnlyThroughS3"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.data.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "audit_checkpoint_task" {
  name               = "${local.workload_name}-audit-checkpoint-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

resource "aws_iam_role_policy" "audit_checkpoint_task" {
  name   = "append-only-signed-checkpoints"
  role   = aws_iam_role.audit_checkpoint_task.id
  policy = data.aws_iam_policy_document.audit_checkpoint_task.json
}

resource "aws_ecs_task_definition" "audit_checkpoint" {
  family                   = "${local.workload_name}-audit-checkpoint"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.audit_checkpoint_execution.arn
  task_role_arn            = aws_iam_role.audit_checkpoint_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "audit-checkpoint"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-audit-checkpoint"]
    command                = ["publish"]
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    environment = [
      { name = "AWS_REGION", value = var.aws_region },
      { name = "RUST_LOG", value = "info,snowman_audit_checkpoint=info" },
      { name = "SNOWMAN_AUDIT_CHECKPOINT_BUCKET", value = aws_s3_bucket.object["audit"].id },
      { name = "SNOWMAN_AUDIT_CHECKPOINT_DB_ROLE", value = "snowman_audit_checkpoint" },
      { name = "SNOWMAN_AUDIT_CHECKPOINT_ENCRYPTION_KEY_ARN", value = aws_kms_key.data.arn },
      { name = "SNOWMAN_AUDIT_CHECKPOINT_SIGNING_KEY_ARN", value = aws_kms_key.audit_checkpoint.arn },
      { name = "SNOWMAN_BUILD_SHA256", value = local.audit_checkpoint_build_sha256 },
      { name = "SNOWMAN_DATABASE_SCHEMA_SHA256", value = var.audit_checkpoint_database_schema_sha256 },
    ]
    secrets = [{
      name      = "DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.audit_checkpoint_runtime.arn}:DATABASE_URL::"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["audit-checkpoint"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "checkpoint"
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])
}

data "aws_iam_policy_document" "audit_checkpoint_scheduler_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.expected_workload_account_id]
    }
  }
}

resource "aws_iam_role" "audit_checkpoint_scheduler" {
  name               = "${local.workload_name}-audit-checkpoint-scheduler"
  assume_role_policy = data.aws_iam_policy_document.audit_checkpoint_scheduler_trust.json
}

data "aws_iam_policy_document" "audit_checkpoint_scheduler" {
  statement {
    effect    = "Allow"
    actions   = ["ecs:RunTask"]
    resources = [aws_ecs_task_definition.audit_checkpoint.arn]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.command_center.arn]
    }
  }
  statement {
    effect  = "Allow"
    actions = ["iam:PassRole"]
    resources = [
      aws_iam_role.audit_checkpoint_execution.arn,
      aws_iam_role.audit_checkpoint_task.arn,
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "audit_checkpoint_scheduler" {
  name   = "run-exact-checkpoint-task"
  role   = aws_iam_role.audit_checkpoint_scheduler.id
  policy = data.aws_iam_policy_document.audit_checkpoint_scheduler.json
}

resource "aws_cloudwatch_event_rule" "audit_checkpoint" {
  name                = "${local.workload_name}-audit-checkpoint"
  description         = "Periodic KMS-signed immutable Snowman audit anchor"
  schedule_expression = var.audit_checkpoint_schedule_expression
  state               = var.audit_checkpoint_schedule_enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "audit_checkpoint" {
  rule     = aws_cloudwatch_event_rule.audit_checkpoint.name
  arn      = aws_ecs_cluster.command_center.arn
  role_arn = aws_iam_role.audit_checkpoint_scheduler.arn

  ecs_target {
    task_definition_arn = aws_ecs_task_definition.audit_checkpoint.arn
    task_count          = 1
    launch_type         = "FARGATE"
    platform_version    = "LATEST"
    network_configuration {
      subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
      security_groups  = [aws_security_group.audit_checkpoint.id]
      assign_public_ip = false
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "audit_checkpoint_failure" {
  name           = "${local.workload_name}-audit-checkpoint-failure"
  log_group_name = aws_cloudwatch_log_group.runtime["audit-checkpoint"].name
  pattern        = "{ $.event = \"audit_checkpoint_failure\" }"
  metric_transformation {
    name      = "AuditCheckpointFailure"
    namespace = "Snowman/CommandCenter"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "audit_checkpoint_failure" {
  alarm_name          = "${local.workload_name}-audit-checkpoint-failure"
  alarm_description   = "Any signature, immutable-history, database anchor, or publication failure"
  namespace           = "Snowman/CommandCenter"
  metric_name         = "AuditCheckpointFailure"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
}
resource "aws_cloudwatch_metric_alarm" "audit_checkpoint_schedule_failure" {
  alarm_name          = "${local.workload_name}-audit-checkpoint-schedule-failure"
  alarm_description   = "EventBridge could not launch the exact checkpoint task"
  namespace           = "AWS/Events"
  metric_name         = "FailedInvocations"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { RuleName = aws_cloudwatch_event_rule.audit_checkpoint.name }
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
}
