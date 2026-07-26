data "aws_iam_policy_document" "ecs_task_trust" {
  statement {
    sid     = "EcsTasksOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.expected_workload_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:ecs:${var.aws_region}:${var.expected_workload_account_id}:*"]
    }
  }
}

resource "aws_secretsmanager_secret" "relay_runtime" {
  name                    = "/snowman/command-center/${var.environment}/relay-runtime"
  description             = "Relay runtime values populated only by the governed database/key bootstrap"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_iam_role" "relay_execution" {
  name               = "${local.workload_name}-relay-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "relay_execution" {
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
    sid    = "RelayLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.runtime["relay"].arn}:*"]
  }
  statement {
    sid       = "ExactRuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.relay_runtime.arn]
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

resource "aws_iam_role_policy" "relay_execution" {
  name   = "exact-runtime-material"
  role   = aws_iam_role.relay_execution.id
  policy = data.aws_iam_policy_document.relay_execution.json
}

resource "aws_iam_role" "relay_task" {
  name               = "${local.workload_name}-relay-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "relay_task" {
  statement {
    sid       = "ConnectExactValkeyIdentity"
    effect    = "Allow"
    actions   = ["elasticache:Connect"]
    resources = [aws_elasticache_replication_group.valkey.arn, aws_elasticache_user.relay.arn]
  }
  statement {
    sid       = "ListRelayMedia"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:ListBucketMultipartUploads"]
    resources = [aws_s3_bucket.media.arn]
  }
  statement {
    sid    = "RelayMediaObjects"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:GetObjectTagging",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
      "s3:PutObjectTagging",
    ]
    resources = ["${aws_s3_bucket.media.arn}/*"]
  }
  statement {
    sid    = "MediaEncryptionOnlyThroughS3"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = [aws_kms_key.data.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "relay_task" {
  name   = "relay-runtime-least-privilege"
  role   = aws_iam_role.relay_task.id
  policy = data.aws_iam_policy_document.relay_task.json
}

resource "aws_ecs_task_definition" "relay" {
  family                   = "${local.workload_name}-relay"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.relay_execution.arn
  task_role_arn            = aws_iam_role.relay_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  ephemeral_storage {
    size_in_gib = 25
  }

  volume { name = "relay-tmp" }
  volume { name = "relay-work" }

  container_definitions = jsonencode([
    {
      name                   = "relay"
      image                  = var.container_image
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001"
      stopTimeout            = 60
      linuxParameters = {
        initProcessEnabled = true
        capabilities = {
          drop = ["ALL"]
        }
      }
      portMappings = [
        { name = "relay", containerPort = 8080, hostPort = 8080, protocol = "tcp", appProtocol = "http" },
        { name = "health", containerPort = 8081, hostPort = 8081, protocol = "tcp", appProtocol = "http" },
        { name = "metrics", containerPort = 9102, hostPort = 9102, protocol = "tcp", appProtocol = "http" },
      ]
      mountPoints = [
        { sourceVolume = "relay-tmp", containerPath = "/tmp", readOnly = false },
        { sourceVolume = "relay-work", containerPath = "/var/lib/snowman", readOnly = false },
      ]
      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "BUZZ_AUDIT_ENABLED", value = "true" },
        { name = "BUZZ_AUTO_MIGRATE", value = "false" },
        { name = "BUZZ_BIND_ADDR", value = "0.0.0.0:8080" },
        { name = "BUZZ_CORS_ORIGINS", value = "https://${var.application_hostname}" },
        { name = "BUZZ_GIT_PACK_CACHE_PATH", value = "/var/lib/snowman/git-pack-cache" },
        { name = "BUZZ_GIT_REPO_PATH", value = "/var/lib/snowman/git" },
        { name = "BUZZ_HEALTH_PORT", value = "8081" },
        { name = "BUZZ_MEDIA_BASE_URL", value = "https://${var.application_hostname}/media" },
        { name = "BUZZ_METRICS_PORT", value = "9102" },
        { name = "BUZZ_REQUIRE_AUTH_TOKEN", value = "true" },
        { name = "BUZZ_REQUIRE_RELAY_MEMBERSHIP", value = "true" },
        { name = "BUZZ_S3_ACCESS_KEY", value = "" },
        { name = "BUZZ_S3_BUCKET", value = aws_s3_bucket.media.id },
        { name = "BUZZ_S3_ENDPOINT", value = "https://s3.${var.aws_region}.amazonaws.com" },
        { name = "BUZZ_S3_REGION", value = var.aws_region },
        { name = "BUZZ_S3_SECRET_KEY", value = "" },
        { name = "REDIS_URL", value = "rediss://${aws_elasticache_replication_group.valkey.primary_endpoint_address}:${aws_elasticache_replication_group.valkey.port}" },
        { name = "RELAY_URL", value = "wss://${var.application_hostname}" },
        { name = "RUST_LOG", value = "info,buzz_relay=info" },
        { name = "SNOWMAN_ANALYST_EVENT_API_ENABLED", value = "false" },
        { name = "SNOWMAN_ROLE_SCOPES", value = "true" },
        { name = "SNOWMAN_VALKEY_CACHE_NAME", value = aws_elasticache_replication_group.valkey.replication_group_id },
        { name = "SNOWMAN_VALKEY_IAM_ENABLED", value = "true" },
        { name = "SNOWMAN_VALKEY_IAM_USER_ID", value = aws_elasticache_user.relay.user_id },
        { name = "SNOWMAN_WORKFORCE_API_ENABLED", value = "false" },
        { name = "SNOWMAN_WORKFORCE_IDENTITY_REQUIRED", value = "true" },
        { name = "SNOWMAN_WORKFORCE_WORKER_API_ENABLED", value = "false" },
      ]
      secrets = [
        { name = "BUZZ_GIT_HOOK_HMAC_SECRET", valueFrom = "${aws_secretsmanager_secret.relay_runtime.arn}:BUZZ_GIT_HOOK_HMAC_SECRET::" },
        { name = "BUZZ_RELAY_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.relay_runtime.arn}:BUZZ_RELAY_PRIVATE_KEY::" },
        { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.relay_runtime.arn}:DATABASE_URL::" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.runtime["relay"].name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "relay"
          mode                  = "non-blocking"
          max-buffer-size       = "4m"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = var.relay_desired_count == 0
      error_message = "The relay task definition is dormant until a governed runtime secret, Cloudflare-authenticated edge, and database bootstrap pass."
    }
  }
}
