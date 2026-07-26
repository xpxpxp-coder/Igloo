locals {
  model_gateway_principal_contract = [
    for principal_id in sort(keys(var.model_gateway_principals)) : merge(
      var.model_gateway_principals[principal_id],
      {
        principal_id     = principal_id
        model_ids        = sort(tolist(var.model_gateway_principals[principal_id].model_ids))
        specialist_roles = sort(tolist(var.model_gateway_principals[principal_id].specialist_roles))
        capabilities     = sort(tolist(var.model_gateway_principals[principal_id].capabilities))
        classifications  = sort(tolist(var.model_gateway_principals[principal_id].classifications))
      }
    )
  ]
  model_gateway_route_contract = [
    for model_id in sort(keys(var.model_gateway_routes)) : merge(
      var.model_gateway_routes[model_id],
      { model_id = model_id }
    )
  ]
}

check "model_gateway_activation_boundary" {
  assert {
    condition = (
      var.model_gateway_desired_count == 0 ||
      (length(var.model_gateway_principals) > 0 && length(var.model_gateway_routes) > 0)
    )
    error_message = "Active model-gateway tasks require at least one exact principal and private inference route."
  }
  assert {
    condition     = !var.external_model_processors_enabled
    error_message = "This zero-third-party deployment forbids external model processors."
  }
  assert {
    condition = alltrue([
      for policy in values(var.model_gateway_principals) :
      split(":", policy.key_id)[3] == var.aws_region &&
      split(":", policy.key_id)[4] == var.analyst360_workload_account_id
    ])
    error_message = "Every model-gateway caller key must belong to the exact Analyst workload account and region."
  }
}

resource "aws_iam_role" "model_gateway_execution" {
  name               = "${local.workload_name}-model-gateway-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "model_gateway_execution" {
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
    sid       = "ModelGatewayLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["model-gateway"].arn}:*"]
  }
}

resource "aws_iam_role_policy" "model_gateway_execution" {
  name   = "exact-image-and-logs"
  role   = aws_iam_role.model_gateway_execution.id
  policy = data.aws_iam_policy_document.model_gateway_execution.json
}

resource "aws_iam_role" "model_gateway_task" {
  name               = "${local.workload_name}-model-gateway-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "model_gateway_task" {
  statement {
    sid     = "ConnectExactValkeyIdentity"
    effect  = "Allow"
    actions = ["elasticache:Connect"]
    resources = [
      aws_elasticache_replication_group.valkey.arn,
      aws_elasticache_user.model_gateway.arn,
    ]
  }
  dynamic "statement" {
    for_each = length(var.model_gateway_principals) == 0 ? [] : [1]
    content {
      sid       = "VerifyExactAnalystWorkloadKeys"
      effect    = "Allow"
      actions   = ["kms:Verify"]
      resources = sort(distinct([for policy in values(var.model_gateway_principals) : policy.key_id]))
    }
  }
}

resource "aws_iam_role_policy" "model_gateway_task" {
  name   = "model-gateway-least-privilege"
  role   = aws_iam_role.model_gateway_task.id
  policy = data.aws_iam_policy_document.model_gateway_task.json
}

resource "aws_ecs_task_definition" "model_gateway" {
  family                   = "${local.workload_name}-model-gateway"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.model_gateway_execution.arn
  task_role_arn            = aws_iam_role.model_gateway_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "model-gateway"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-model-gateway"]
    stopTimeout            = 60
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    portMappings = [{
      name          = "model-gateway"
      containerPort = 8443
      hostPort      = 8443
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      { name = "AWS_REGION", value = var.aws_region },
      { name = "RUST_LOG", value = "snowman_model_gateway=info" },
      { name = "SNOWMAN_MODEL_GATEWAY_BIND_ADDR", value = "0.0.0.0:8443" },
      { name = "SNOWMAN_MODEL_GATEWAY_PRINCIPALS_JSON", value = jsonencode(local.model_gateway_principal_contract) },
      { name = "SNOWMAN_MODEL_GATEWAY_REDIS_URL", value = "rediss://${aws_elasticache_replication_group.valkey.primary_endpoint_address}:${aws_elasticache_replication_group.valkey.port}" },
      { name = "SNOWMAN_MODEL_GATEWAY_ROUTES_JSON", value = jsonencode(local.model_gateway_route_contract) },
      { name = "SNOWMAN_MODEL_GATEWAY_TIMEOUT_SECONDS", value = "60" },
      { name = "SNOWMAN_MODEL_GATEWAY_VALKEY_CACHE_NAME", value = aws_elasticache_replication_group.valkey.replication_group_id },
      { name = "SNOWMAN_MODEL_GATEWAY_VALKEY_IAM_USER_ID", value = aws_elasticache_user.model_gateway.user_id },
    ]
    healthCheck = {
      command     = ["CMD-SHELL", "curl --fail --silent http://127.0.0.1:8443/_readiness >/dev/null || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["model-gateway"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "model-gateway"
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.model_gateway_desired_count == 0
      error_message = "The model gateway remains hard-zero until private ingress, a pinned inference image, and staging zero-egress tests pass."
    }
  }
}

resource "aws_ecs_service" "model_gateway" {
  name            = "${local.workload_name}-model-gateway"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.model_gateway.arn
  desired_count   = var.model_gateway_desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.model_gateway.id]
    assign_public_ip = false
  }
}
