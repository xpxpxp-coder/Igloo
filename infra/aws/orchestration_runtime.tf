# Dormant, private orchestration API and tenant-isolated delivery workers.
# No resource in this file creates a public route or direct internet egress.

variable "orchestration_private_ingress_enabled" {
  type        = bool
  description = "Create the cost-bearing private TLS NLB only after staging evidence is accepted."
  default     = false
}

variable "orchestration_private_dns_name" {
  type        = string
  description = "Exact private Snowman API hostname."
  default     = ""
}

variable "orchestration_tls_certificate_arn" {
  type        = string
  description = "Local-account ACM certificate for the exact private orchestration hostname."
  default     = ""
}

variable "orchestration_model_route_profiles" {
  description = "Reviewed mapping from opaque orchestration routes to coordinator runtime/model policy."
  type = list(object({
    model_route_reference = string
    runtime_id            = string
    model_id              = string
    specialist_role       = string
    classification        = string
    system_prompt         = string
    max_input_tokens      = number
    max_output_tokens     = number
  }))
  default = []
}

variable "orchestration_worker_profiles" {
  description = "One hard-dormant, identity-isolated scheduler/delivery profile per tenant workspace."
  type = map(object({
    tenant_id             = string
    workspace_id          = string
    service_identity_id   = string
    service_principal     = string
    policy_generation     = number
    orchestration_origin  = string
    coordinator_origin    = string
    reminder_relay_origin = string
    reminder_channel_id   = string
  }))
  default = {}
}

locals {
  orchestration_expected_dns_name = var.environment == "staging" ? "orchestration.staging.internal.snowmanai.org" : "orchestration.internal.snowmanai.org"
}

check "orchestration_runtime_activation_boundary" {
  assert {
    condition = !var.orchestration_private_ingress_enabled || (
      var.orchestration_private_dns_name == local.orchestration_expected_dns_name &&
      try(split(":", var.orchestration_tls_certificate_arn)[3], "") == var.aws_region &&
      try(split(":", var.orchestration_tls_certificate_arn)[4], "") == var.expected_workload_account_id
    )
    error_message = "Orchestration ingress requires the exact private Snowman hostname and a local ACM certificate."
  }
  assert {
    condition = alltrue([
      for profile in values(var.orchestration_worker_profiles) :
      startswith(profile.orchestration_origin, "https://") &&
      startswith(profile.coordinator_origin, "https://") &&
      startswith(profile.reminder_relay_origin, "https://") &&
      endswith(trimsuffix(profile.orchestration_origin, "/"), ".internal.snowmanai.org") &&
      endswith(trimsuffix(profile.coordinator_origin, "/"), ".internal.snowmanai.org") &&
      endswith(trimsuffix(profile.reminder_relay_origin, "/"), ".internal.snowmanai.org")
    ])
    error_message = "Every orchestration destination must be an exact private Snowman HTTPS origin."
  }
}

resource "aws_secretsmanager_secret" "orchestration_runtime" {
  name                    = "/snowman/command-center/${var.environment}/orchestration-runtime"
  description             = "Orchestration-only database URL populated by governed bootstrap"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "orchestration_worker_identity" {
  for_each = var.orchestration_worker_profiles

  name                    = "/snowman/command-center/${var.environment}/orchestration-worker/${each.key}"
  description             = "Exact scheduler and reminder signing keys; values populated out of band"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_cloudwatch_log_group" "orchestration_runtime" {
  for_each = toset(["api", "worker"])

  name              = "/snowman/command-center/${var.environment}/orchestration-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_security_group" "orchestration_api" {
  name        = "${local.workload_name}-orchestration-api"
  description = "Private orchestration API; database and AWS endpoints only"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "orchestration_worker" {
  name        = "${local.workload_name}-orchestration-worker"
  description = "Fixed Snowman orchestration, coordinator, and reminder destinations only"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "orchestration_ingress" {
  name        = "${local.workload_name}-orchestration-ingress"
  description = "Private TLS entry for orchestration workers only"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_vpc_security_group_ingress_rule" "orchestration_api_from_ingress" {
  security_group_id            = aws_security_group.orchestration_api.id
  referenced_security_group_id = aws_security_group.orchestration_ingress.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "orchestration_ingress_from_worker" {
  security_group_id            = aws_security_group.orchestration_ingress.id
  referenced_security_group_id = aws_security_group.orchestration_worker.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_ingress_to_api" {
  security_group_id            = aws_security_group.orchestration_ingress.id
  referenced_security_group_id = aws_security_group.orchestration_api.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "database_from_orchestration_api" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.orchestration_api.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_api_to_database" {
  security_group_id            = aws_security_group.orchestration_api.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_api_to_endpoints" {
  security_group_id            = aws_security_group.orchestration_api.id
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_worker_to_ingress" {
  security_group_id            = aws_security_group.orchestration_worker.id
  referenced_security_group_id = aws_security_group.orchestration_ingress.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "agent_coordinator_from_orchestration_worker" {
  security_group_id            = aws_security_group.agent_coordinator_ingress.id
  referenced_security_group_id = aws_security_group.orchestration_worker.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "workforce_relay_from_orchestration_worker" {
  security_group_id            = aws_security_group.workforce_ingress.id
  referenced_security_group_id = aws_security_group.orchestration_worker.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_worker_to_coordinator" {
  security_group_id            = aws_security_group.orchestration_worker.id
  referenced_security_group_id = aws_security_group.agent_coordinator_ingress.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_worker_to_relay" {
  security_group_id            = aws_security_group.orchestration_worker.id
  referenced_security_group_id = aws_security_group.workforce_ingress.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_worker_to_endpoints" {
  security_group_id            = aws_security_group.orchestration_worker.id
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_dns_udp" {
  for_each = {
    api    = aws_security_group.orchestration_api.id
    worker = aws_security_group.orchestration_worker.id
  }
  security_group_id = each.value
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_egress_rule" "orchestration_dns_tcp" {
  for_each = {
    api    = aws_security_group.orchestration_api.id
    worker = aws_security_group.orchestration_worker.id
  }
  security_group_id = each.value
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
}

resource "aws_lb" "orchestration_private" {
  count = var.orchestration_private_ingress_enabled ? 1 : 0

  name                             = substr("${local.workload_name}-orchestration", 0, 32)
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
  security_groups                  = [aws_security_group.orchestration_ingress.id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = true
}

resource "aws_lb_target_group" "orchestration_private" {
  count       = var.orchestration_private_ingress_enabled ? 1 : 0
  name        = substr("${local.workload_name}-orchestration", 0, 32)
  port        = 8080
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.command_center.id
  health_check {
    protocol = "HTTP"
    path     = "/_readiness"
    matcher  = "200-299"
  }
}

resource "aws_lb_listener" "orchestration_private" {
  count             = var.orchestration_private_ingress_enabled ? 1 : 0
  load_balancer_arn = aws_lb.orchestration_private[0].arn
  port              = 443
  protocol          = "TLS"
  certificate_arn   = var.orchestration_tls_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.orchestration_private[0].arn
  }
}

resource "aws_route53_zone" "orchestration_private" {
  count = var.orchestration_private_ingress_enabled ? 1 : 0
  name  = var.orchestration_private_dns_name
  vpc { vpc_id = aws_vpc.command_center.id }
}

resource "aws_route53_record" "orchestration_private" {
  count   = var.orchestration_private_ingress_enabled ? 1 : 0
  zone_id = aws_route53_zone.orchestration_private[0].zone_id
  name    = var.orchestration_private_dns_name
  type    = "A"
  alias {
    name                   = aws_lb.orchestration_private[0].dns_name
    zone_id                = aws_lb.orchestration_private[0].zone_id
    evaluate_target_health = true
  }
}

resource "aws_iam_role" "orchestration_api_execution" {
  name               = "${local.workload_name}-orchestration-api-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "orchestration_api_execution" {
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
    effect    = "Allow"
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["arn:${data.aws_partition.current.partition}:ecr:${var.aws_region}:${var.expected_workload_account_id}:repository/snowman-command-center"]
    effect    = "Allow"
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.orchestration_runtime["api"].arn}:*"]
    effect    = "Allow"
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.orchestration_runtime.arn]
    effect    = "Allow"
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
    effect    = "Allow"
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "orchestration_api_execution" {
  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.orchestration_api_execution.id
  policy = data.aws_iam_policy_document.orchestration_api_execution.json
}

resource "aws_iam_role" "orchestration_worker_execution" {
  for_each           = var.orchestration_worker_profiles
  name               = "${local.workload_name}-orchestration-${each.key}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "orchestration_worker_execution" {
  for_each = var.orchestration_worker_profiles
  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
    effect    = "Allow"
  }
  statement {
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["arn:${data.aws_partition.current.partition}:ecr:${var.aws_region}:${var.expected_workload_account_id}:repository/snowman-command-center"]
    effect    = "Allow"
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.orchestration_runtime["worker"].arn}:*"]
    effect    = "Allow"
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.orchestration_worker_identity[each.key].arn]
    effect    = "Allow"
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
    effect    = "Allow"
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "orchestration_worker_execution" {
  for_each = var.orchestration_worker_profiles
  name     = "exact-image-secret-and-logs"
  role     = aws_iam_role.orchestration_worker_execution[each.key].id
  policy   = data.aws_iam_policy_document.orchestration_worker_execution[each.key].json
}

resource "aws_ecs_task_definition" "orchestration_api" {
  family                   = "${local.workload_name}-orchestration-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.orchestration_api_execution.arn
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  container_definitions = jsonencode([{
    name                   = "orchestration-api", image = var.container_image, essential = true,
    readonlyRootFilesystem = true, privileged = false, user = "10001",
    entryPoint             = ["/usr/local/bin/snowman-orchestration-service"], stopTimeout = 60,
    linuxParameters        = { initProcessEnabled = true, capabilities = { drop = ["ALL"] } },
    portMappings           = [{ name = "orchestration-api", containerPort = 8080, hostPort = 8080, protocol = "tcp", appProtocol = "http" }],
    environment = [
      { name = "SNOWMAN_ORCHESTRATION_BIND_ADDR", value = "0.0.0.0:8080" },
      { name = "SNOWMAN_ORCHESTRATION_DATABASE_ROLE", value = "snowman_orchestration" },
      { name = "SNOWMAN_ORCHESTRATION_NETWORK_POLICY", value = "private-snowman-only" },
      { name = "SNOWMAN_ORCHESTRATION_PUBLIC_ORIGIN", value = var.orchestration_private_dns_name == "" ? "https://${local.orchestration_expected_dns_name}/" : "https://${var.orchestration_private_dns_name}/" },
    ],
    secrets          = [{ name = "SNOWMAN_ORCHESTRATION_DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.orchestration_runtime.arn}:DATABASE_URL::" }],
    healthCheck      = { command = ["CMD-SHELL", "curl --fail --silent http://127.0.0.1:8080/_readiness >/dev/null || exit 1"], interval = 30, timeout = 5, retries = 3, startPeriod = 30 },
    logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.orchestration_runtime["api"].name, awslogs-region = var.aws_region, awslogs-stream-prefix = "api", mode = "non-blocking", max-buffer-size = "1m" } }
  }])
}

resource "aws_ecs_service" "orchestration_api" {
  name                   = "${local.workload_name}-orchestration-api"
  cluster                = aws_ecs_cluster.command_center.id
  task_definition        = aws_ecs_task_definition.orchestration_api.arn
  desired_count          = 0
  launch_type            = "FARGATE"
  enable_execute_command = false
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  dynamic "load_balancer" {
    for_each = var.orchestration_private_ingress_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.orchestration_private[0].arn
      container_name   = "orchestration-api"
      container_port   = 8080
    }
  }
  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.orchestration_api.id]
    assign_public_ip = false
  }
  depends_on = [aws_lb_listener.orchestration_private]
}

resource "aws_ecs_task_definition" "orchestration_worker" {
  for_each                 = var.orchestration_worker_profiles
  family                   = "${local.workload_name}-orchestration-worker-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.orchestration_worker_execution[each.key].arn
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  container_definitions = jsonencode([{
    name                   = "orchestration-worker-${each.key}", image = var.container_image, essential = true,
    readonlyRootFilesystem = true, privileged = false, user = "10001",
    entryPoint             = ["/usr/local/bin/snowman-orchestration-worker"], stopTimeout = 60,
    linuxParameters        = { initProcessEnabled = true, capabilities = { drop = ["ALL"] } },
    environment = [
      { name = "SNOWMAN_ORCHESTRATION_WORKER_ORIGIN", value = each.value.orchestration_origin },
      { name = "SNOWMAN_ORCHESTRATION_COORDINATOR_ORIGIN", value = each.value.coordinator_origin },
      { name = "SNOWMAN_ORCHESTRATION_REMINDER_ORIGIN", value = each.value.reminder_relay_origin },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_TENANT_ID", value = each.value.tenant_id },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_WORKSPACE_ID", value = each.value.workspace_id },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_IDENTITY_ID", value = each.value.service_identity_id },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_SERVICE_PRINCIPAL", value = each.value.service_principal },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_POLICY_GENERATION", value = tostring(each.value.policy_generation) },
      { name = "SNOWMAN_ORCHESTRATION_REMINDER_CHANNEL_ID", value = each.value.reminder_channel_id },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_INTERVAL_SECONDS", value = "15" },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_REQUEST_TIMEOUT_SECONDS", value = "15" },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_LEASE_SECONDS", value = "90" },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_MAX_RECORDS", value = "8" },
      { name = "SNOWMAN_ORCHESTRATION_WORKER_SUBMITTED_TIMEOUT_SECONDS", value = "120" },
    ],
    secrets = [
      { name = "SNOWMAN_ORCHESTRATION_WORKER_NOSTR_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.orchestration_worker_identity[each.key].arn}:SNOWMAN_ORCHESTRATION_WORKER_NOSTR_PRIVATE_KEY::" },
      { name = "SNOWMAN_ORCHESTRATION_REMINDER_NOSTR_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.orchestration_worker_identity[each.key].arn}:SNOWMAN_ORCHESTRATION_REMINDER_NOSTR_PRIVATE_KEY::" },
    ],
    logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.orchestration_runtime["worker"].name, awslogs-region = var.aws_region, awslogs-stream-prefix = each.key, mode = "non-blocking", max-buffer-size = "1m" } }
  }])
}

resource "aws_ecs_service" "orchestration_worker" {
  for_each               = var.orchestration_worker_profiles
  name                   = "${local.workload_name}-orchestration-worker-${each.key}"
  cluster                = aws_ecs_cluster.command_center.id
  task_definition        = aws_ecs_task_definition.orchestration_worker[each.key].arn
  desired_count          = 0
  launch_type            = "FARGATE"
  enable_execute_command = false
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.orchestration_worker.id]
    assign_public_ip = false
  }
}

resource "aws_cloudwatch_metric_alarm" "orchestration_api_cpu" {
  alarm_name          = "${local.workload_name}-orchestration-api-cpu"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { ClusterName = aws_ecs_cluster.command_center.name, ServiceName = aws_ecs_service.orchestration_api.name }
  alarm_actions       = [aws_sns_topic.operations.arn]
}

output "orchestration_runtime_posture" {
  description = "Hard-dormant orchestration execution coordinates; no raw request, message, provider, or client content is exported."
  value = {
    api_desired_count       = aws_ecs_service.orchestration_api.desired_count
    api_task_definition_arn = aws_ecs_task_definition.orchestration_api.arn
    worker_desired_counts   = { for name, service in aws_ecs_service.orchestration_worker : name => service.desired_count }
    runtime_secret_arn      = aws_secretsmanager_secret.orchestration_runtime.arn
    database_role           = "snowman_orchestration"
    private_ingress_enabled = var.orchestration_private_ingress_enabled
    public_ingress          = false
    direct_internet_egress  = false
  }
}
