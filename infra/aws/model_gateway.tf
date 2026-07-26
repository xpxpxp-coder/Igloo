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
  assert {
    condition = !var.model_gateway_private_ingress_enabled || (
      length(var.model_gateway_consumer_principal_arns) > 0 &&
      split(":", var.model_gateway_tls_certificate_arn)[3] == var.aws_region &&
      split(":", var.model_gateway_tls_certificate_arn)[4] == var.expected_workload_account_id &&
      alltrue([
        for arn in var.model_gateway_consumer_principal_arns :
        split(":", arn)[4] == var.analyst360_workload_account_id
      ])
    )
    error_message = "Private model-gateway ingress requires a local-region certificate and only exact Analyst-account consumer principals."
  }
}

resource "aws_security_group" "model_gateway_private_link_nlb" {
  count = var.model_gateway_private_ingress_enabled ? 1 : 0

  name        = "${local.workload_name}-model-gateway-private-link"
  description = "PrivateLink-only NLB path to the Snowman model gateway"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_vpc_security_group_egress_rule" "model_gateway_private_link_to_gateway" {
  count = var.model_gateway_private_ingress_enabled ? 1 : 0

  security_group_id            = aws_security_group.model_gateway_private_link_nlb[0].id
  referenced_security_group_id = aws_security_group.model_gateway.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "TLS termination NLB to the policy gateway only"
}

resource "aws_vpc_security_group_ingress_rule" "model_gateway_from_private_link" {
  count = var.model_gateway_private_ingress_enabled ? 1 : 0

  security_group_id            = aws_security_group.model_gateway.id
  referenced_security_group_id = aws_security_group.model_gateway_private_link_nlb[0].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "PrivateLink NLB to model gateway only"
}

resource "aws_lb" "model_gateway_private" {
  count = var.model_gateway_private_ingress_enabled ? 1 : 0

  name                                                         = substr("${local.workload_name}-models", 0, 32)
  internal                                                     = true
  load_balancer_type                                           = "network"
  subnets                                                      = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
  security_groups                                              = [aws_security_group.model_gateway_private_link_nlb[0].id]
  enforce_security_group_inbound_rules_on_private_link_traffic = "off"
  enable_cross_zone_load_balancing                             = true
  enable_deletion_protection                                   = var.deletion_protection
}

resource "aws_lb_target_group" "model_gateway_private" {
  count = var.model_gateway_private_ingress_enabled ? 1 : 0

  name        = substr("${local.workload_name}-models", 0, 32)
  port        = 8443
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.command_center.id

  deregistration_delay = 30
  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/_readiness"
    port                = "traffic-port"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    timeout             = 5
  }
}

resource "aws_lb_listener" "model_gateway_private" {
  count = var.model_gateway_private_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.model_gateway_private[0].arn
  port              = 443
  protocol          = "TLS"
  certificate_arn   = var.model_gateway_tls_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.model_gateway_private[0].arn
  }
}

resource "aws_vpc_endpoint_service" "model_gateway" {
  count = var.model_gateway_private_ingress_enabled ? 1 : 0

  acceptance_required        = true
  network_load_balancer_arns = [aws_lb.model_gateway_private[0].arn]
  allowed_principals         = sort(tolist(var.model_gateway_consumer_principal_arns))
  private_dns_name           = var.model_gateway_private_dns_name
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
  dynamic "statement" {
    for_each = length([
      for route in values(var.model_gateway_routes) : route
      if route.backend_kind == "sagemaker"
    ]) == 0 ? [] : [1]
    content {
      sid     = "InvokeExactSnowmanSageMakerEndpoints"
      effect  = "Allow"
      actions = ["sagemaker:InvokeEndpoint"]
      resources = sort(concat(
        [
          for route in values(var.model_gateway_routes) :
          "arn:${data.aws_partition.current.partition}:sagemaker:${var.aws_region}:${var.expected_workload_account_id}:endpoint/${route.sagemaker_endpoint_name}"
          if route.backend_kind == "sagemaker"
        ],
        [
          for route in values(var.model_gateway_routes) :
          "arn:${data.aws_partition.current.partition}:sagemaker:${var.aws_region}:${var.expected_workload_account_id}:inference-component/${route.sagemaker_inference_component_name}"
          if route.backend_kind == "sagemaker"
        ]
      ))
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

  dynamic "load_balancer" {
    for_each = var.model_gateway_private_ingress_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.model_gateway_private[0].arn
      container_name   = "model-gateway"
      container_port   = 8443
    }
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.model_gateway.id]
    assign_public_ip = false
  }

  depends_on = [aws_lb_listener.model_gateway_private]
}
