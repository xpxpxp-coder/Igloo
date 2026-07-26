locals {
  workforce_role_capabilities = {
    lead                  = ["workforce.plan", "workforce.tasks.execute"]
    governed_analyst      = ["analytics.query", "workforce.context.write", "workforce.tasks.execute"]
    client_delivery       = ["artifact.build", "workforce.context.read", "workforce.context.write", "workforce.tasks.execute"]
    quality_risk_reviewer = ["artifact.build", "artifact.review", "workforce.context.read", "workforce.context.write", "workforce.tasks.execute"]
    research_evidence     = ["evidence.manifest.read", "workforce.context.write", "workforce.tasks.execute"]
    scheduler             = ["workforce.maintenance"]
    trigger               = ["workforce.proactive.propose", "workforce.schedules.trigger"]
    deadline_operations   = ["deadline.remind", "workforce.tasks.execute"]
  }
  workforce_team_identity_ids = {
    lead                  = try(one([for profile in values(var.workforce_profiles) : profile.identity_id if profile.specialist_role == "lead"]), "")
    governed_analyst      = try(one([for profile in values(var.workforce_profiles) : profile.identity_id if profile.specialist_role == "governed_analyst"]), "")
    client_delivery       = try(one([for profile in values(var.workforce_profiles) : profile.identity_id if profile.specialist_role == "client_delivery"]), "")
    quality_risk_reviewer = try(one([for profile in values(var.workforce_profiles) : profile.identity_id if profile.specialist_role == "quality_risk_reviewer"]), "")
  }
  workforce_team_model_overrides = {
    governed_analyst      = try(one([for profile in values(var.workforce_profiles) : profile.model_override if profile.specialist_role == "governed_analyst"]), null)
    client_delivery       = try(one([for profile in values(var.workforce_profiles) : profile.model_override if profile.specialist_role == "client_delivery"]), null)
    quality_risk_reviewer = try(one([for profile in values(var.workforce_profiles) : profile.model_override if profile.specialist_role == "quality_risk_reviewer"]), null)
  }
  workforce_bootstrap_enabled = var.workforce_community_id != ""
  configured_worker_desired_count = sum(concat(
    [0], [for profile in values(var.workforce_profiles) : profile.desired_count]
  ))
  configured_scheduler_desired_count = sum(concat(
    [0], [for profile in values(var.scheduler_profiles) : profile.desired_count]
  ))
  configured_trigger_desired_count = sum(concat(
    [0], [for profile in values(var.trigger_profiles) : profile.desired_count]
  ))
  configured_reminder_desired_count = sum(concat(
    [0], [for profile in values(var.reminder_profiles) : profile.desired_count]
  ))
  workforce_identity_secret_arns = concat(
    [for secret in values(aws_secretsmanager_secret.workforce_identity) : secret.arn],
    [for secret in values(aws_secretsmanager_secret.workforce_scheduler_identity) : secret.arn],
    [for secret in values(aws_secretsmanager_secret.workforce_trigger_identity) : secret.arn],
    [for secret in values(aws_secretsmanager_secret.workforce_reminder_identity) : secret.arn],
  )
  workforce_bootstrap_manifest = local.workforce_bootstrap_enabled ? jsonencode({
    schema_version = "snowman.workforce.bootstrap.v1"
    community_id   = var.workforce_community_id
    community_host = var.workforce_community_host
    identities = concat(
      [for name in sort(keys(var.workforce_profiles)) : {
        identity_id     = var.workforce_profiles[name].identity_id
        display_name    = var.workforce_profiles[name].display_name
        specialist_role = var.workforce_profiles[name].specialist_role
        capabilities    = local.workforce_role_capabilities[var.workforce_profiles[name].specialist_role]
        secret_arn      = aws_secretsmanager_secret.workforce_identity[name].arn
        secret_kind     = "worker"
      }],
      [for name in sort(keys(var.scheduler_profiles)) : {
        identity_id     = var.scheduler_profiles[name].identity_id
        display_name    = "Snowman ${title(replace(name, "-", " "))} Scheduler"
        specialist_role = "scheduler"
        capabilities    = local.workforce_role_capabilities.scheduler
        secret_arn      = aws_secretsmanager_secret.workforce_scheduler_identity[name].arn
        secret_kind     = "scheduler"
      }],
      [for name in sort(keys(var.trigger_profiles)) : {
        identity_id     = var.trigger_profiles[name].identity_id
        display_name    = "Snowman ${title(replace(name, "-", " "))} Trigger"
        specialist_role = "trigger"
        capabilities    = local.workforce_role_capabilities.trigger
        secret_arn      = aws_secretsmanager_secret.workforce_trigger_identity[name].arn
        secret_kind     = "trigger"
      }],
      [for name in sort(keys(var.reminder_profiles)) : {
        identity_id     = var.reminder_profiles[name].identity_id
        display_name    = "Snowman ${title(replace(name, "-", " "))} Reminder"
        specialist_role = "deadline_operations"
        capabilities    = local.workforce_role_capabilities.deadline_operations
        secret_arn      = aws_secretsmanager_secret.workforce_reminder_identity[name].arn
        secret_kind     = "reminder"
      }],
    )
    model_routes = [for model_id in sort(keys(var.workforce_model_routes)) : {
      model_id                             = model_id
      gateway_url                          = var.workforce_model_gateway_url
      suited_roles                         = sort(tolist(var.workforce_model_routes[model_id].suited_roles))
      allowed_classifications              = sort(tolist(var.workforce_model_routes[model_id].allowed_classifications))
      quality_score                        = var.workforce_model_routes[model_id].quality_score
      latency_score                        = var.workforce_model_routes[model_id].latency_score
      max_cost_microusd_per_million_tokens = var.workforce_model_routes[model_id].max_cost_microusd_per_million_tokens
      max_context_tokens                   = var.workforce_model_routes[model_id].max_context_tokens
      evaluation_evidence_sha256           = var.workforce_model_routes[model_id].evaluation_evidence_sha256
      evaluated_at                         = var.workforce_model_routes[model_id].evaluated_at
    }]
    team = {
      lead                  = local.workforce_team_identity_ids.lead
      governed_analyst      = local.workforce_team_identity_ids.governed_analyst
      client_delivery       = local.workforce_team_identity_ids.client_delivery
      quality_risk_reviewer = local.workforce_team_identity_ids.quality_risk_reviewer
      model_overrides       = local.workforce_team_model_overrides
    }
  }) : ""
}

check "workforce_profile_boundary" {
  assert {
    condition     = local.configured_worker_desired_count == var.worker_desired_count
    error_message = "worker_desired_count must exactly equal the sum of per-identity workforce profile counts."
  }
  assert {
    condition = local.workforce_bootstrap_enabled == (
      length(var.workforce_profiles) > 0 ||
      length(var.scheduler_profiles) > 0 ||
      length(var.trigger_profiles) > 0 ||
      length(var.reminder_profiles) > 0 ||
      length(var.workforce_model_routes) > 0 ||
      var.workforce_community_host != ""
    )
    error_message = "The workforce community and its service/model manifest must be configured together."
  }
  assert {
    condition = !local.workforce_bootstrap_enabled || (
      alltrue([for identity_id in values(local.workforce_team_identity_ids) : identity_id != ""]) &&
      length([for profile in values(var.workforce_profiles) : profile if profile.specialist_role == "lead"]) == 1 &&
      length([for profile in values(var.workforce_profiles) : profile if profile.specialist_role == "governed_analyst"]) == 1 &&
      length([for profile in values(var.workforce_profiles) : profile if profile.specialist_role == "client_delivery"]) == 1 &&
      length([for profile in values(var.workforce_profiles) : profile if profile.specialist_role == "quality_risk_reviewer"]) == 1 &&
      length(var.scheduler_profiles) >= 1 &&
      length(var.trigger_profiles) >= 1 &&
      length(var.reminder_profiles) >= 1 &&
      length(var.workforce_model_routes) >= 1 &&
      var.workforce_model_gateway_url != "" &&
      var.workforce_community_host != "" &&
      var.workforce_lead_identity_id == local.workforce_team_identity_ids.lead
    )
    error_message = "A workforce bootstrap requires one lead/analyst/delivery/reviewer, plus scheduler, trigger, reminder, evaluated model route, Snowman gateway, and matching lead identity."
  }
  assert {
    condition = !local.workforce_bootstrap_enabled || alltrue([
      for role, model_id in local.workforce_team_model_overrides :
      model_id == null || try(contains(var.workforce_model_routes[model_id].suited_roles, role), false)
    ])
    error_message = "Every team model override must name an evaluated route suited to that exact specialist role."
  }
  assert {
    condition = !local.workforce_bootstrap_enabled || (
      try(contains(var.workforce_model_routes[var.workforce_planning_model_id].suited_roles, "lead"), false) &&
      alltrue(flatten([
        for role in ["lead", "governed_analyst", "client_delivery", "quality_risk_reviewer", "deadline_operations"] : [
          for classification in ["internal", "confidential", "restricted"] :
          anytrue([
            for route in values(var.workforce_model_routes) :
            contains(route.suited_roles, role) && contains(route.allowed_classifications, classification)
          ])
        ]
      ]))
    )
    error_message = "The planning route must serve lead work, and every required team/reminder role needs an evaluated route for every classification."
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
    condition     = local.configured_reminder_desired_count == var.reminder_desired_count
    error_message = "reminder_desired_count must exactly equal the sum of per-identity reminder profile counts."
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
      [for profile in values(var.trigger_profiles) : profile.identity_id],
      [for profile in values(var.reminder_profiles) : profile.identity_id]
    ))) == length(var.workforce_profiles) + length(var.scheduler_profiles) + length(var.trigger_profiles) + length(var.reminder_profiles)
    error_message = "Worker, scheduler, trigger, and reminder profiles must use distinct service identities."
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
    condition = !var.workforce_api_enabled || (
      var.workforce_lead_identity_id != "" &&
      contains([for profile in values(var.workforce_profiles) : profile.identity_id], var.workforce_lead_identity_id) &&
      var.workforce_model_gateway_url != "" &&
      var.workforce_planning_model_id != ""
    )
    error_message = "An active workforce API requires an exact configured lead profile and evaluated Snowman planning route."
  }
  assert {
    condition     = length(var.proactive_automatic_capabilities) == 0 || var.proactive_max_automatic_cost_microusd > 0
    error_message = "Automatic capabilities require a positive hard per-action cost ceiling."
  }
  assert {
    condition = alltrue(concat(
      [for profile in values(var.workforce_profiles) : contains(var.workforce_private_hostnames, trimprefix(profile.relay_url, "https://"))],
      [for profile in values(var.scheduler_profiles) : contains(var.workforce_private_hostnames, trimprefix(profile.relay_url, "https://"))],
      [for profile in values(var.trigger_profiles) : contains(var.workforce_private_hostnames, trimprefix(profile.relay_url, "https://"))],
      [for profile in values(var.reminder_profiles) : contains(var.workforce_private_hostnames, trimprefix(profile.relay_url, "https://"))]
    ))
    error_message = "Every private workforce caller must use an exact allowlisted Snowman hostname protected by internal TLS and split-horizon DNS."
  }
  assert {
    condition = (
      (var.worker_desired_count == 0 && var.scheduler_desired_count == 0 && var.trigger_desired_count == 0 && var.reminder_desired_count == 0) ||
      (
        var.workforce_private_ingress_enabled &&
        length(var.workforce_private_hostnames) > 0 &&
        var.workforce_api_enabled &&
        var.workforce_worker_api_enabled &&
        var.relay_desired_count > 0
      )
    )
    error_message = "Active workers, schedulers, triggers, or reminders require the governed workforce APIs, private TLS relay origin, and at least one relay task."
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

resource "aws_secretsmanager_secret" "workforce_reminder_identity" {
  for_each = var.reminder_profiles

  name                    = "/snowman/command-center/${var.environment}/workforce-reminder/${each.key}"
  description             = "Nostr private key for one fixed-content Snowman reminder identity"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_iam_role" "workforce_reminder_execution" {
  for_each = var.reminder_profiles

  name               = "${local.workload_name}-reminder-${each.key}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "workforce_reminder_execution" {
  for_each = var.reminder_profiles

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
    sid       = "ExactReminderSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.workforce_reminder_identity[each.key].arn]
  }
  statement {
    sid       = "ReminderSecretKey"
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
    sid       = "ReminderLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["workforce-reminder"].arn}:*"]
  }
}

resource "aws_iam_role_policy" "workforce_reminder_execution" {
  for_each = var.reminder_profiles

  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.workforce_reminder_execution[each.key].id
  policy = data.aws_iam_policy_document.workforce_reminder_execution[each.key].json
}

resource "aws_iam_role" "workforce_reminder_task" {
  for_each = var.reminder_profiles

  name               = "${local.workload_name}-reminder-${each.key}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

resource "aws_ecs_task_definition" "workforce_reminder" {
  for_each = var.reminder_profiles

  family                   = "${local.workload_name}-reminder-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.workforce_reminder_execution[each.key].arn
  task_role_arn            = aws_iam_role.workforce_reminder_task[each.key].arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "reminder-${each.key}"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-workforce-reminder"]
    stopTimeout            = 30
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    environment = [
      { name = "RUST_LOG", value = "snowman_workforce_reminder=info" },
      { name = "SNOWMAN_WORKFORCE_RELAY_URL", value = each.value.relay_url },
      { name = "SNOWMAN_WORKFORCE_REMINDER_IDENTITY_ID", value = each.value.identity_id },
      { name = "SNOWMAN_WORKFORCE_REMINDER_INTERVAL_SECONDS", value = "15" },
    ]
    secrets = [
      { name = "SNOWMAN_WORKFORCE_REMINDER_NOSTR_PRIVATE_KEY", valueFrom = "${aws_secretsmanager_secret.workforce_reminder_identity[each.key].arn}:SNOWMAN_WORKFORCE_REMINDER_NOSTR_PRIVATE_KEY::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["workforce-reminder"].name
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
      error_message = "Reminder profiles remain hard-zero until private relay, identity, and staged lost-response tests pass."
    }
  }
}

resource "aws_ecs_service" "workforce_reminder" {
  for_each = var.reminder_profiles

  name            = "${local.workload_name}-reminder-${each.key}"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.workforce_reminder[each.key].arn
  desired_count   = each.value.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.reminder.id]
    assign_public_ip = false
  }
}
