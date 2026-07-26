locals {
  configured_worker_desired_count = sum(concat(
    [0], [for profile in values(var.workforce_profiles) : profile.desired_count]
  ))
  configured_scheduler_desired_count = sum(concat(
    [0], [for profile in values(var.scheduler_profiles) : profile.desired_count]
  ))
  configured_trigger_desired_count = sum(concat(
    [0], [for profile in values(var.trigger_profiles) : profile.desired_count]
  ))
}

check "workforce_profile_boundary" {
  assert {
    condition     = local.configured_worker_desired_count == var.worker_desired_count
    error_message = "worker_desired_count must exactly equal the sum of per-identity workforce profile counts."
  }
  assert {
    condition     = local.configured_scheduler_desired_count == var.scheduler_desired_count
    error_message = "scheduler_desired_count must exactly equal the sum of per-identity scheduler profile counts."
  }
  assert {
    condition     = local.configured_trigger_desired_count == var.trigger_desired_count
    error_message = "trigger_desired_count must exactly equal the sum of per-identity trigger profile counts."
  }
  assert {
    condition = alltrue([
      for profile in values(var.workforce_profiles) :
      split(":", profile.analyst_signing_key_arn)[3] == var.aws_region &&
      split(":", profile.analyst_signing_key_arn)[4] == var.analyst360_workload_account_id
    ])
    error_message = "Every workforce signing key must belong to the exact Analyst 360 workload account and region."
  }
  assert {
    condition = length(distinct(concat(
      [for profile in values(var.workforce_profiles) : profile.identity_id],
      [for profile in values(var.scheduler_profiles) : profile.identity_id],
      [for profile in values(var.trigger_profiles) : profile.identity_id]
    ))) == length(var.workforce_profiles) + length(var.scheduler_profiles) + length(var.trigger_profiles)
    error_message = "Worker, scheduler, and trigger profiles must use distinct service identities."
  }
  assert {
    condition = length(distinct([
      for profile in values(var.workforce_profiles) : profile.identity_id
    ])) == length(var.workforce_profiles)
    error_message = "Every workforce profile must use a distinct service identity."
  }
  assert {
    condition = length(distinct([
      for profile in values(var.workforce_profiles) : profile.analyst_service_principal
    ])) == length(var.workforce_profiles)
    error_message = "Every workforce profile must use a distinct Analyst service principal."
  }
  assert {
    condition = length(distinct([
      for profile in values(var.workforce_profiles) : profile.analyst_signing_key_arn
    ])) == length(var.workforce_profiles)
    error_message = "Every workforce profile must use a distinct asymmetric KMS signing key."
  }
  assert {
    condition     = var.worker_desired_count == 0 || var.analyst360_private_prefix_list_id != ""
    error_message = "Active workforce tasks require the exact private Analyst 360 prefix list."
  }
  assert {
    condition = alltrue(concat(
      [for profile in values(var.workforce_profiles) : contains(var.workforce_private_hostnames, trimprefix(profile.relay_url, "https://"))],
      [for profile in values(var.scheduler_profiles) : contains(var.workforce_private_hostnames, trimprefix(profile.relay_url, "https://"))],
      [for profile in values(var.trigger_profiles) : contains(var.workforce_private_hostnames, trimprefix(profile.relay_url, "https://"))]
    ))
    error_message = "Every private workforce caller must use an exact allowlisted Snowman hostname protected by internal TLS and split-horizon DNS."
  }
  assert {
    condition = (
      (var.worker_desired_count == 0 && var.scheduler_desired_count == 0 && var.trigger_desired_count == 0) ||
      (
        var.workforce_private_ingress_enabled &&
        length(var.workforce_private_hostnames) > 0 &&
        var.workforce_api_enabled &&
        var.workforce_worker_api_enabled &&
        var.relay_desired_count > 0
      )
    )
    error_message = "Active workers, schedulers, or triggers require the governed workforce APIs, private TLS relay origin, and at least one relay task."
  }
}

resource "aws_lb" "workforce_private" {
  count = var.workforce_private_ingress_enabled ? 1 : 0

  name                       = "snowman-cc-${var.environment}-work"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.workforce_ingress.id]
  subnets                    = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  enable_http2               = true
  idle_timeout               = 300
  preserve_host_header       = true
}

resource "aws_lb_target_group" "workforce_relay" {
  count = var.workforce_private_ingress_enabled ? 1 : 0

  name                 = "snowman-cc-${var.environment}-work"
  port                 = 8080
  protocol             = "HTTP"
  protocol_version     = "HTTP1"
  target_type          = "ip"
  vpc_id               = aws_vpc.command_center.id
  deregistration_delay = 30

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    timeout             = 5
    path                = "/_readiness"
    port                = "8081"
    protocol            = "HTTP"
    matcher             = "200"
  }
}

resource "aws_lb_listener" "workforce_https" {
  count = var.workforce_private_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.workforce_private[0].arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.acm_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.workforce_relay[0].arn
  }
}

resource "aws_route53_zone" "workforce_private" {
  for_each = var.workforce_private_ingress_enabled ? var.workforce_private_hostnames : toset([])

  name = each.value
  vpc { vpc_id = aws_vpc.command_center.id }
}

resource "aws_route53_record" "workforce_private" {
  for_each = aws_route53_zone.workforce_private

  zone_id = each.value.zone_id
  name    = each.key
  type    = "A"
  alias {
    name                   = aws_lb.workforce_private[0].dns_name
    zone_id                = aws_lb.workforce_private[0].zone_id
    evaluate_target_health = true
  }
}

resource "aws_secretsmanager_secret" "workforce_identity" {
  for_each = var.workforce_profiles

  name                    = "/snowman/command-center/${var.environment}/workforce/${each.key}"
  description             = "Nostr private key and team identity map for one Snowman workforce identity"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_iam_role" "workforce_execution" {
  for_each = var.workforce_profiles

  name               = "${local.workload_name}-${each.key}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "workforce_execution" {
  for_each = var.workforce_profiles

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
    sid       = "ExactIdentitySecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.workforce_identity[each.key].arn]
  }
  statement {
    sid       = "IdentitySecretKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "WorkforceLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["workforce-worker"].arn}:*"]
  }
}

resource "aws_iam_role_policy" "workforce_execution" {
  for_each = var.workforce_profiles

  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.workforce_execution[each.key].id
  policy = data.aws_iam_policy_document.workforce_execution[each.key].json
}

resource "aws_iam_role" "workforce_task" {
  for_each = var.workforce_profiles

  name               = "${local.workload_name}-${each.key}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "workforce_task" {
  for_each = var.workforce_profiles

  statement {
    sid       = "SignExactAnalystRequests"
    effect    = "Allow"
    actions   = ["kms:Sign"]
    resources = [each.value.analyst_signing_key_arn]
  }
}

resource "aws_iam_role_policy" "workforce_task" {
  for_each = var.workforce_profiles

  name   = "exact-analyst-request-signing-key"
  role   = aws_iam_role.workforce_task[each.key].id
  policy = data.aws_iam_policy_document.workforce_task[each.key].json
}

resource "aws_ecs_task_definition" "workforce" {
  for_each = var.workforce_profiles

  family                   = "${local.workload_name}-workforce-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.workforce_execution[each.key].arn
  task_role_arn            = aws_iam_role.workforce_task[each.key].arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "workforce-${each.key}"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-workforce-worker"]
    stopTimeout            = 60
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    environment = [
      { name = "AWS_REGION", value = var.aws_region },
      { name = "RUST_LOG", value = "snowman_workforce_worker=info" },
      { name = "SNOWMAN_WORKFORCE_RELAY_URL", value = each.value.relay_url },
      { name = "SNOWMAN_WORKFORCE_IDENTITY_ID", value = each.value.identity_id },
      { name = "SNOWMAN_ANALYST_ENDPOINT", value = each.value.analyst_endpoint },
      { name = "SNOWMAN_ANALYST_SERVICE_PRINCIPAL", value = each.value.analyst_service_principal },
      { name = "SNOWMAN_ANALYST_SIGNING_KEY_ARN", value = each.value.analyst_signing_key_arn },
      { name = "SNOWMAN_ANALYST_TENANT_ID", value = each.value.tenant_id },
      { name = "SNOWMAN_ANALYST_CLIENT_ID", value = each.value.client_id },
      { name = "SNOWMAN_ANALYST_PROJECT_ID", value = each.value.project_id },
    ]
    secrets = [
      { name = "SNOWMAN_WORKFORCE_NOSTR_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.workforce_identity[each.key].arn}:SNOWMAN_WORKFORCE_NOSTR_PRIVATE_KEY::" },
      { name = "SNOWMAN_WORKFORCE_TEAM_IDENTITIES_JSON", valueFrom = "${aws_secretsmanager_secret.workforce_identity[each.key].arn}:SNOWMAN_WORKFORCE_TEAM_IDENTITIES_JSON::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["workforce-worker"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = each.key
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = each.value.desired_count == 0
      error_message = "Workforce profiles remain hard-zero until private routing, executor handlers, and staging safety gates pass."
    }
  }
}

resource "aws_ecs_service" "workforce" {
  for_each = var.workforce_profiles

  name            = "${local.workload_name}-workforce-${each.key}"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.workforce[each.key].arn
  desired_count   = each.value.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.worker.id]
    assign_public_ip = false
  }
}

resource "aws_vpc_security_group_egress_rule" "worker_to_analyst360" {
  count = var.analyst360_private_prefix_list_id == "" ? 0 : 1

  security_group_id = aws_security_group.worker.id
  prefix_list_id    = var.analyst360_private_prefix_list_id
  description       = "Exact cross-account private Analyst 360 endpoint"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_secretsmanager_secret" "workforce_scheduler_identity" {
  for_each = var.scheduler_profiles

  name                    = "/snowman/command-center/${var.environment}/workforce-scheduler/${each.key}"
  description             = "Nostr private key for one maintenance-only Snowman scheduler identity"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_iam_role" "workforce_scheduler_execution" {
  for_each = var.scheduler_profiles

  name               = "${local.workload_name}-scheduler-${each.key}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "workforce_scheduler_execution" {
  for_each = var.scheduler_profiles

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
    sid       = "ExactSchedulerSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.workforce_scheduler_identity[each.key].arn]
  }
  statement {
    sid       = "SchedulerSecretKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "SchedulerLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["workforce-scheduler"].arn}:*"]
  }
}

resource "aws_iam_role_policy" "workforce_scheduler_execution" {
  for_each = var.scheduler_profiles

  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.workforce_scheduler_execution[each.key].id
  policy = data.aws_iam_policy_document.workforce_scheduler_execution[each.key].json
}

resource "aws_iam_role" "workforce_scheduler_task" {
  for_each = var.scheduler_profiles

  name               = "${local.workload_name}-scheduler-${each.key}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

resource "aws_ecs_task_definition" "workforce_scheduler" {
  for_each = var.scheduler_profiles

  family                   = "${local.workload_name}-scheduler-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.workforce_scheduler_execution[each.key].arn
  task_role_arn            = aws_iam_role.workforce_scheduler_task[each.key].arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "scheduler-${each.key}"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-workforce-scheduler"]
    stopTimeout            = 30
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    environment = [
      { name = "RUST_LOG", value = "snowman_workforce_scheduler=info" },
      { name = "SNOWMAN_WORKFORCE_RELAY_URL", value = each.value.relay_url },
      { name = "SNOWMAN_WORKFORCE_SCHEDULER_IDENTITY_ID", value = each.value.identity_id },
      { name = "SNOWMAN_WORKFORCE_MAINTENANCE_INTERVAL_SECONDS", value = "30" },
    ]
    secrets = [
      { name = "SNOWMAN_WORKFORCE_SCHEDULER_NOSTR_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.workforce_scheduler_identity[each.key].arn}:SNOWMAN_WORKFORCE_SCHEDULER_NOSTR_PRIVATE_KEY::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["workforce-scheduler"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = each.key
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = each.value.desired_count == 0
      error_message = "Scheduler profiles remain hard-zero until private relay routing and staging recovery tests pass."
    }
  }
}

resource "aws_ecs_service" "workforce_scheduler" {
  for_each = var.scheduler_profiles

  name            = "${local.workload_name}-scheduler-${each.key}"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.workforce_scheduler[each.key].arn
  desired_count   = each.value.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.scheduler.id]
    assign_public_ip = false
  }
}

resource "aws_secretsmanager_secret" "workforce_trigger_identity" {
  for_each = var.trigger_profiles

  name                    = "/snowman/command-center/${var.environment}/workforce-trigger/${each.key}"
  description             = "Nostr private key for one proposal-only Snowman recurring-work trigger"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_iam_role" "workforce_trigger_execution" {
  for_each = var.trigger_profiles

  name               = "${local.workload_name}-trigger-${each.key}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "workforce_trigger_execution" {
  for_each = var.trigger_profiles

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
    sid       = "ExactTriggerSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.workforce_trigger_identity[each.key].arn]
  }
  statement {
    sid       = "TriggerSecretKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.data.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "TriggerLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["workforce-trigger"].arn}:*"]
  }
}

resource "aws_iam_role_policy" "workforce_trigger_execution" {
  for_each = var.trigger_profiles

  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.workforce_trigger_execution[each.key].id
  policy = data.aws_iam_policy_document.workforce_trigger_execution[each.key].json
}

resource "aws_iam_role" "workforce_trigger_task" {
  for_each = var.trigger_profiles

  name               = "${local.workload_name}-trigger-${each.key}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

resource "aws_ecs_task_definition" "workforce_trigger" {
  for_each = var.trigger_profiles

  family                   = "${local.workload_name}-trigger-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.workforce_trigger_execution[each.key].arn
  task_role_arn            = aws_iam_role.workforce_trigger_task[each.key].arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "trigger-${each.key}"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-workforce-trigger"]
    stopTimeout            = 30
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    environment = [
      { name = "RUST_LOG", value = "snowman_workforce_trigger=info" },
      { name = "SNOWMAN_WORKFORCE_RELAY_URL", value = each.value.relay_url },
      { name = "SNOWMAN_WORKFORCE_TRIGGER_IDENTITY_ID", value = each.value.identity_id },
      { name = "SNOWMAN_WORKFORCE_TRIGGER_INTERVAL_SECONDS", value = "30" },
    ]
    secrets = [
      { name = "SNOWMAN_WORKFORCE_TRIGGER_NOSTR_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.workforce_trigger_identity[each.key].arn}:SNOWMAN_WORKFORCE_TRIGGER_NOSTR_PRIVATE_KEY::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["workforce-trigger"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = each.key
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = each.value.desired_count == 0
      error_message = "Trigger profiles remain hard-zero until private relay and staged lost-response tests pass."
    }
  }
}

resource "aws_ecs_service" "workforce_trigger" {
  for_each = var.trigger_profiles

  name            = "${local.workload_name}-trigger-${each.key}"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.workforce_trigger[each.key].arn
  desired_count   = each.value.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.trigger.id]
    assign_public_ip = false
  }
}
