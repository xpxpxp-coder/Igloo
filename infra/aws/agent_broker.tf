locals {
  agent_broker_expected_dns_name = var.environment == "staging" ? "agents.staging.internal.snowmanai.org" : "agents.internal.snowmanai.org"
  agent_broker_allowed_origins = var.agent_broker_private_dns_name == "" ? [] : [
    "https://${var.agent_broker_private_dns_name}",
    "https://${var.agent_broker_private_dns_name}/",
    "https://${var.agent_broker_private_dns_name}:443",
    "https://${var.agent_broker_private_dns_name}:443/",
  ]
}

check "agent_broker_activation_boundary" {
  assert {
    condition = !var.agent_broker_private_ingress_enabled || (
      var.agent_broker_private_dns_name == local.agent_broker_expected_dns_name &&
      contains(local.agent_broker_allowed_origins, var.agent_broker_url) &&
      try(split(":", var.agent_broker_tls_certificate_arn)[3], "") == var.aws_region &&
      try(split(":", var.agent_broker_tls_certificate_arn)[4], "") == var.expected_workload_account_id
    )
    error_message = "Private agent-broker ingress requires the exact stage hostname/origin and a local-account, local-region ACM certificate."
  }
  assert {
    condition     = var.agent_broker_desired_count == 0
    error_message = "The agent broker remains hard-zero until bootstrap, coordinator, model-token, and live zero-egress staging evidence pass."
  }
}

resource "aws_lb" "agent_broker_private" {
  count = var.agent_broker_private_ingress_enabled ? 1 : 0

  name                             = substr("${local.workload_name}-agents", 0, 32)
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
  security_groups                  = [aws_security_group.agent_broker_ingress.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = true
}

resource "aws_lb_target_group" "agent_broker_private" {
  count = var.agent_broker_private_ingress_enabled ? 1 : 0

  name        = substr("${local.workload_name}-agents", 0, 32)
  port        = 8080
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.command_center.id

  deregistration_delay = 30
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

resource "aws_lb_listener" "agent_broker_private" {
  count = var.agent_broker_private_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.agent_broker_private[0].arn
  port              = 443
  protocol          = "TLS"
  certificate_arn   = var.agent_broker_tls_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.agent_broker_private[0].arn
  }
}

resource "aws_route53_zone" "agent_broker_private" {
  count = var.agent_broker_private_ingress_enabled ? 1 : 0

  name = var.agent_broker_private_dns_name
  vpc { vpc_id = aws_vpc.command_center.id }
}

resource "aws_route53_record" "agent_broker_private" {
  count = var.agent_broker_private_ingress_enabled ? 1 : 0

  zone_id = aws_route53_zone.agent_broker_private[0].zone_id
  name    = var.agent_broker_private_dns_name
  type    = "A"
  alias {
    name                   = aws_lb.agent_broker_private[0].dns_name
    zone_id                = aws_lb.agent_broker_private[0].zone_id
    evaluate_target_health = true
  }
}

resource "aws_iam_role" "agent_broker_execution" {
  name               = "${local.workload_name}-agent-broker-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "agent_broker_execution" {
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
    sid       = "AgentBrokerLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["agent-broker"].arn}:*"]
  }
  statement {
    sid       = "ExactAgentBrokerRuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.agent_broker_runtime.arn]
  }
  statement {
    sid       = "AgentBrokerSecretKey"
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

resource "aws_iam_role_policy" "agent_broker_execution" {
  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.agent_broker_execution.id
  policy = data.aws_iam_policy_document.agent_broker_execution.json
}

resource "aws_ecs_task_definition" "agent_broker" {
  family                   = "${local.workload_name}-agent-broker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.agent_broker_execution.arn

  # Deliberately omit task_role_arn. PostgreSQL authenticates with the exact
  # password-only broker role; the serving process needs no AWS authority.

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "agent-broker"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    privileged             = false
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-agent-broker"]
    stopTimeout            = 60
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    portMappings = [{
      name          = "agent-broker"
      containerPort = 8080
      hostPort      = 8080
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      { name = "SNOWMAN_AGENT_BROKER_BIND_ADDR", value = "0.0.0.0:8080" },
      { name = "SNOWMAN_AGENT_BROKER_DATABASE_ROLE", value = "snowman_agent_broker" },
      { name = "SNOWMAN_AGENT_BROKER_MAX_CONNECTIONS", value = "8" },
      { name = "SNOWMAN_AGENT_BROKER_NETWORK_POLICY", value = "private-snowman-only" },
    ]
    secrets = [{
      name      = "SNOWMAN_AGENT_BROKER_DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.agent_broker_runtime.arn}:database_url::"
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
        awslogs-group         = aws_cloudwatch_log_group.runtime["agent-broker"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "agent-broker"
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.agent_broker_desired_count == 0
      error_message = "The agent broker remains hard-zero until its remaining activation evidence passes."
    }
  }
}

resource "aws_ecs_service" "agent_broker" {
  name            = "${local.workload_name}-agent-broker"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.agent_broker.arn
  desired_count   = var.agent_broker_desired_count
  launch_type     = "FARGATE"

  enable_execute_command = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  dynamic "load_balancer" {
    for_each = var.agent_broker_private_ingress_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.agent_broker_private[0].arn
      container_name   = "agent-broker"
      container_port   = 8080
    }
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.agent_broker.id]
    assign_public_ip = false
  }

  depends_on = [aws_lb_listener.agent_broker_private]
}
