locals {
  agent_coordinator_expected_dns_name = var.environment == "staging" ? "coordinator.staging.internal.snowmanai.org" : "coordinator.internal.snowmanai.org"
  agent_coordinator_public_origin     = var.agent_coordinator_private_dns_name == "" ? "" : "https://${var.agent_coordinator_private_dns_name}/"
  agent_coordinator_runtime_profiles = [
    for name in sort(keys(aws_ecs_task_definition.agent_executor)) : {
      runtime_id          = var.agent_runtime_profiles[name].runtime_id
      task_definition_arn = aws_ecs_task_definition.agent_executor[name].arn
      container_name      = "agent-${name}"
    }
  ]
  agent_executor_task_arns = [
    for name in sort(keys(aws_ecs_task_definition.agent_executor)) : aws_ecs_task_definition.agent_executor[name].arn
  ]
  agent_executor_execution_role_arns = [
    for name in sort(keys(aws_iam_role.agent_executor_execution)) : aws_iam_role.agent_executor_execution[name].arn
  ]
}

check "agent_coordinator_activation_boundary" {
  assert {
    condition = !var.agent_coordinator_private_ingress_enabled || (
      var.agent_coordinator_private_dns_name == local.agent_coordinator_expected_dns_name &&
      try(split(":", var.agent_coordinator_tls_certificate_arn)[3], "") == var.aws_region &&
      try(split(":", var.agent_coordinator_tls_certificate_arn)[4], "") == var.expected_workload_account_id
    )
    error_message = "Private agent-coordinator ingress requires the exact stage hostname and a local-account, local-region ACM certificate."
  }
  assert {
    condition     = var.agent_coordinator_desired_count == 0
    error_message = "The agent coordinator remains hard-zero until live identity, cancellation, model-token, and zero-egress staging evidence pass."
  }
}

resource "aws_kms_key" "agent_job_token" {
  description                        = "Deterministic one-job Snowman agent credential derivation"
  key_usage                          = "GENERATE_VERIFY_MAC"
  customer_master_key_spec           = "HMAC_256"
  enable_key_rotation                = false
  deletion_window_in_days            = 30
  bypass_policy_lockout_safety_check = false
}

resource "aws_kms_alias" "agent_job_token" {
  name          = "alias/${local.workload_name}-agent-job-token"
  target_key_id = aws_kms_key.agent_job_token.key_id
}

resource "aws_lb" "agent_coordinator_private" {
  count = var.agent_coordinator_private_ingress_enabled ? 1 : 0

  name                             = substr("${local.workload_name}-coordinator", 0, 32)
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
  security_groups                  = [aws_security_group.agent_coordinator_ingress.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = true
}

resource "aws_lb_target_group" "agent_coordinator_private" {
  count = var.agent_coordinator_private_ingress_enabled ? 1 : 0

  name        = substr("${local.workload_name}-coordinator", 0, 32)
  port        = 8080
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.command_center.id

  deregistration_delay = 30
  preserve_client_ip   = true
  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = "/_readiness"
    port                = "traffic-port"
    matcher             = "200-299"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    timeout             = 5
  }
}

resource "aws_lb_listener" "agent_coordinator_private" {
  count = var.agent_coordinator_private_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.agent_coordinator_private[0].arn
  port              = 443
  protocol          = "TLS"
  certificate_arn   = var.agent_coordinator_tls_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.agent_coordinator_private[0].arn
  }
}

resource "aws_route53_zone" "agent_coordinator_private" {
  count = var.agent_coordinator_private_ingress_enabled ? 1 : 0

  name = var.agent_coordinator_private_dns_name
  vpc { vpc_id = aws_vpc.command_center.id }
}

resource "aws_route53_record" "agent_coordinator_private" {
  count = var.agent_coordinator_private_ingress_enabled ? 1 : 0

  zone_id = aws_route53_zone.agent_coordinator_private[0].zone_id
  name    = var.agent_coordinator_private_dns_name
  type    = "A"
  alias {
    name                   = aws_lb.agent_coordinator_private[0].dns_name
    zone_id                = aws_lb.agent_coordinator_private[0].zone_id
    evaluate_target_health = true
  }
}

resource "aws_iam_role" "agent_coordinator_execution" {
  name               = "${local.workload_name}-agent-coordinator-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "agent_coordinator_execution" {
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
    sid       = "AgentCoordinatorLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["agent-coordinator"].arn}:*"]
  }
  statement {
    sid       = "ExactAgentCoordinatorRuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.agent_coordinator_runtime.arn]
  }
  statement {
    sid       = "AgentCoordinatorSecretKey"
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

resource "aws_iam_role_policy" "agent_coordinator_execution" {
  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.agent_coordinator_execution.id
  policy = data.aws_iam_policy_document.agent_coordinator_execution.json
}

resource "aws_iam_role" "agent_coordinator_task" {
  name               = "${local.workload_name}-agent-coordinator-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "agent_coordinator_task" {
  statement {
    sid       = "ExactJobTokenHmac"
    effect    = "Allow"
    actions   = ["kms:GenerateMac"]
    resources = [aws_kms_key.agent_job_token.arn]
  }

  dynamic "statement" {
    for_each = length(local.agent_executor_task_arns) > 0 ? [1] : []
    content {
      sid       = "ExactAgentTaskDefinitions"
      effect    = "Allow"
      actions   = ["ecs:RunTask"]
      resources = local.agent_executor_task_arns
      condition {
        test     = "ArnEquals"
        variable = "ecs:cluster"
        values   = [aws_ecs_cluster.command_center.arn]
      }
    }
  }

  statement {
    sid     = "ExactAgentTasks"
    effect  = "Allow"
    actions = ["ecs:DescribeTasks", "ecs:StopTask"]
    resources = [
      "arn:${data.aws_partition.current.partition}:ecs:${var.aws_region}:${var.expected_workload_account_id}:task/${aws_ecs_cluster.command_center.name}/*"
    ]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.command_center.arn]
    }
  }

  dynamic "statement" {
    for_each = length(local.agent_executor_execution_role_arns) > 0 ? [1] : []
    content {
      sid       = "PassOnlyAgentExecutionRoles"
      effect    = "Allow"
      actions   = ["iam:PassRole"]
      resources = local.agent_executor_execution_role_arns
      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["ecs-tasks.amazonaws.com"]
      }
    }
  }
}

resource "aws_iam_role_policy" "agent_coordinator_task" {
  name   = "exact-job-token-and-ecs-launch"
  role   = aws_iam_role.agent_coordinator_task.id
  policy = data.aws_iam_policy_document.agent_coordinator_task.json
}

resource "aws_ecs_task_definition" "agent_coordinator" {
  family                   = "${local.workload_name}-agent-coordinator"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.agent_coordinator_execution.arn
  task_role_arn            = aws_iam_role.agent_coordinator_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "agent-coordinator"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    privileged             = false
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-agent-coordinator"]
    stopTimeout            = 60
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    portMappings = [{
      name          = "agent-coordinator"
      containerPort = 8080
      hostPort      = 8080
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      { name = "SNOWMAN_AGENT_COORDINATOR_BIND_ADDR", value = "0.0.0.0:8080" },
      { name = "SNOWMAN_AGENT_COORDINATOR_DATABASE_ROLE", value = "snowman_agent_coordinator" },
      { name = "SNOWMAN_AGENT_COORDINATOR_MAX_CONNECTIONS", value = "8" },
      { name = "SNOWMAN_AGENT_COORDINATOR_NETWORK_POLICY", value = "private-snowman-only" },
      { name = "SNOWMAN_AGENT_COORDINATOR_PUBLIC_ORIGIN", value = local.agent_coordinator_public_origin },
      { name = "SNOWMAN_AGENT_COORDINATOR_ECS_CLUSTER_ARN", value = aws_ecs_cluster.command_center.arn },
      { name = "SNOWMAN_AGENT_COORDINATOR_PRIVATE_SUBNET_IDS_JSON", value = jsonencode([for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]) },
      { name = "SNOWMAN_AGENT_COORDINATOR_EXECUTOR_SECURITY_GROUP_ID", value = aws_security_group.agent_executor.id },
      { name = "SNOWMAN_AGENT_COORDINATOR_RUNTIME_PROFILES_JSON", value = jsonencode(local.agent_coordinator_runtime_profiles) },
      { name = "SNOWMAN_AGENT_COORDINATOR_TOKEN_HMAC_KEY_ARN", value = aws_kms_key.agent_job_token.arn },
    ]
    secrets = [{
      name      = "SNOWMAN_AGENT_COORDINATOR_DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.agent_coordinator_runtime.arn}:DATABASE_URL::"
    }]
    healthCheck = {
      command     = ["CMD-SHELL", "curl --fail --silent http://127.0.0.1:8080/_readiness >/dev/null || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["agent-coordinator"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "agent-coordinator"
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.agent_coordinator_desired_count == 0
      error_message = "The agent coordinator remains hard-zero until its activation evidence passes."
    }
    precondition {
      condition = var.agent_coordinator_desired_count == 0 || (
        var.agent_coordinator_private_ingress_enabled &&
        length(local.agent_coordinator_runtime_profiles) > 0
      )
      error_message = "Coordinator activation requires private TLS ingress and at least one reviewed runtime profile."
    }
  }
}

resource "aws_ecs_service" "agent_coordinator" {
  name            = "${local.workload_name}-agent-coordinator"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.agent_coordinator.arn
  desired_count   = var.agent_coordinator_desired_count
  launch_type     = "FARGATE"

  enable_execute_command = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  dynamic "load_balancer" {
    for_each = var.agent_coordinator_private_ingress_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.agent_coordinator_private[0].arn
      container_name   = "agent-coordinator"
      container_port   = 8080
    }
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.agent_coordinator.id]
    assign_public_ip = false
  }

  depends_on = [aws_lb_listener.agent_coordinator_private]
}
