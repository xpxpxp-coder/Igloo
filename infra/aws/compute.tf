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

resource "aws_secretsmanager_secret" "agent_broker_runtime" {
  name                    = "/snowman/command-center/${var.environment}/agent-broker-runtime"
  description             = "Private agent broker database URL populated only by the governed bootstrap"
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
  dynamic "statement" {
    for_each = var.workforce_identity_authority == null ? [] : [var.workforce_identity_authority]
    content {
      sid       = "VerifyExactWorkforceIdentityAuthority"
      effect    = "Allow"
      actions   = ["kms:Verify"]
      resources = [statement.value.signing_kms_key_arn]
    }
  }
}

resource "aws_iam_role_policy" "relay_task" {
  name   = "relay-runtime-least-privilege"
  role   = aws_iam_role.relay_task.id
  policy = data.aws_iam_policy_document.relay_task.json
}

resource "aws_iam_role" "bootstrap_execution" {
  name               = "${local.workload_name}-bootstrap-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "bootstrap_execution" {
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
    sid    = "MigrationLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.runtime["migration"].arn}:*"]
  }
}

resource "aws_iam_role_policy" "bootstrap_execution" {
  name   = "bootstrap-image-and-logs"
  role   = aws_iam_role.bootstrap_execution.id
  policy = data.aws_iam_policy_document.bootstrap_execution.json
}

resource "aws_iam_role" "bootstrap_task" {
  name               = "${local.workload_name}-bootstrap-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "bootstrap_task" {
  statement {
    sid       = "ReadRdsManagedMasterSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.postgres.master_user_secret[0].secret_arn]
  }
  statement {
    sid    = "ReconcileExactRuntimeSecret"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
    ]
    resources = [
      aws_secretsmanager_secret.relay_runtime.arn,
      aws_secretsmanager_secret.agent_broker_runtime.arn,
    ]
  }
  dynamic "statement" {
    for_each = local.workforce_bootstrap_enabled ? [1] : []
    content {
      sid    = "ReconcileExactWorkforceIdentitySecrets"
      effect = "Allow"
      actions = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
      ]
      resources = local.workforce_identity_secret_arns
    }
  }
  statement {
    sid    = "SecretEncryptionOnlyThroughSecretsManager"
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
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "bootstrap_task" {
  name   = "governed-database-and-key-bootstrap"
  role   = aws_iam_role.bootstrap_task.id
  policy = data.aws_iam_policy_document.bootstrap_task.json
}

resource "aws_ecs_task_definition" "bootstrap" {
  family                   = "${local.workload_name}-bootstrap"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.bootstrap_execution.arn
  task_role_arn            = aws_iam_role.bootstrap_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([
    {
      name                   = "bootstrap"
      image                  = var.container_image
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001"
      entryPoint             = ["/usr/local/bin/snowman-bootstrap"]
      linuxParameters = {
        initProcessEnabled = true
        capabilities = {
          drop = ["ALL"]
        }
      }
      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "SNOWMAN_DATABASE_NAME", value = aws_db_instance.postgres.db_name },
        { name = "SNOWMAN_RDS_MASTER_SECRET_ARN", value = aws_db_instance.postgres.master_user_secret[0].secret_arn },
        { name = "SNOWMAN_RELAY_RUNTIME_SECRET_ARN", value = aws_secretsmanager_secret.relay_runtime.arn },
        { name = "SNOWMAN_RUNTIME_DB_ROLE", value = "snowman_relay_runtime" },
        { name = "SNOWMAN_AGENT_BROKER_RUNTIME_SECRET_ARN", value = aws_secretsmanager_secret.agent_broker_runtime.arn },
        { name = "SNOWMAN_AGENT_BROKER_DB_ROLE", value = "snowman_agent_broker" },
        { name = "SNOWMAN_WORKFORCE_BOOTSTRAP_MANIFEST", value = local.workforce_bootstrap_manifest },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.runtime["migration"].name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "bootstrap"
          mode                  = "non-blocking"
          max-buffer-size       = "1m"
        }
      }
    }
  ])
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
        { name = "SNOWMAN_ANALYST_EVENT_API_ENABLED", value = tostring(var.analyst_event_api_enabled) },
        { name = "SNOWMAN_PARTITION_MAINTENANCE_MODE", value = "external" },
        { name = "SNOWMAN_ROLE_SCOPES", value = "true" },
        { name = "SNOWMAN_VALKEY_CACHE_NAME", value = aws_elasticache_replication_group.valkey.replication_group_id },
        { name = "SNOWMAN_VALKEY_IAM_ENABLED", value = "true" },
        { name = "SNOWMAN_VALKEY_IAM_USER_ID", value = aws_elasticache_user.relay.user_id },
        { name = "SNOWMAN_WORKFORCE_API_ENABLED", value = tostring(var.workforce_api_enabled) },
        { name = "SNOWMAN_WORKFORCE_IDENTITY_REQUIRED", value = "true" },
        { name = "SNOWMAN_WORKFORCE_IDENTITY_API_ENABLED", value = tostring(var.workforce_identity_api_enabled) },
        { name = "SNOWMAN_WORKFORCE_WORKER_API_ENABLED", value = tostring(var.workforce_worker_api_enabled) },
        { name = "SNOWMAN_WORKFORCE_LEAD_IDENTITY_ID", value = var.workforce_lead_identity_id },
        { name = "SNOWMAN_MODEL_GATEWAY_URL", value = var.workforce_model_gateway_url },
        { name = "SNOWMAN_PLANNING_MODEL_ID", value = var.workforce_planning_model_id },
        { name = "SNOWMAN_PROACTIVE_AUTOMATIC_CAPABILITIES", value = join(",", sort(tolist(var.proactive_automatic_capabilities))) },
        { name = "SNOWMAN_PROACTIVE_MAX_AUTOMATIC_COST_MICROUSD", value = tostring(var.proactive_max_automatic_cost_microusd) },
        { name = "SNOWMAN_PROACTIVE_MINIMUM_CONFIDENCE_BASIS_POINTS", value = tostring(var.proactive_minimum_confidence_basis_points) },
      ]
      secrets = [
        { name = "BUZZ_GIT_HOOK_HMAC_SECRET", valueFrom = "${aws_secretsmanager_secret.relay_runtime.arn}:BUZZ_GIT_HOOK_HMAC_SECRET::" },
        { name = "BUZZ_RELAY_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.relay_runtime.arn}:BUZZ_RELAY_PRIVATE_KEY::" },
        { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.relay_runtime.arn}:DATABASE_URL::" },
        { name = "RELAY_OWNER_PUBKEY", valueFrom = "${aws_secretsmanager_secret.relay_runtime.arn}:RELAY_OWNER_PUBKEY::" },
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

resource "aws_ecs_service" "relay" {
  name            = "${local.workload_name}-relay"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.relay.arn
  desired_count   = var.relay_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  dynamic "load_balancer" {
    for_each = var.edge_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.relay[0].arn
      container_name   = "relay"
      container_port   = 8080
    }
  }

  dynamic "load_balancer" {
    for_each = var.workforce_private_ingress_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.workforce_relay[0].arn
      container_name   = "relay"
      container_port   = 8080
    }
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.relay.id]
    assign_public_ip = false
  }

  lifecycle {
    precondition {
      condition     = var.relay_desired_count == 0
      error_message = "The relay service remains hard-zero until bootstrap, private routing, and staged activation gates pass."
    }
  }

  depends_on = [aws_lb_listener.https, aws_lb_listener.workforce_https]
}
