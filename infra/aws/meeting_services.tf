locals {
  meeting_command_expected_dns_name = var.environment == "staging" ? "meeting.staging.internal.snowmanai.org" : "meeting.internal.snowmanai.org"
  meeting_media_runtime_packaged = (
    var.meeting_media_runtime_evidence_sha256 != "" &&
    var.meeting_media_container_entrypoint != ""
  )
  meeting_media_namespace = var.environment == "staging" ? "meeting-media.staging.internal.snowmanai.org" : "meeting-media.internal.snowmanai.org"
}

check "meeting_services_activation_boundary" {
  assert {
    condition = !var.meeting_command_private_ingress_enabled || (
      var.meeting_command_private_dns_name == local.meeting_command_expected_dns_name &&
      var.meeting_command_receiver_identity_id != "" &&
      length(var.meeting_command_consumer_principal_arns) > 0 &&
      try(split(":", var.meeting_command_tls_certificate_arn)[3], "") == var.aws_region &&
      try(split(":", var.meeting_command_tls_certificate_arn)[4], "") == var.expected_workload_account_id &&
      alltrue([
        for arn in var.meeting_command_consumer_principal_arns :
        split(":", arn)[4] == var.analyst360_workload_account_id
      ])
    )
    error_message = "Meeting-command PrivateLink requires the exact stage hostname, registered receiver, local ACM certificate, and only exact Analyst-account principals."
  }

  assert {
    condition = (
      var.meeting_command_desired_count == 0 &&
      var.meeting_media_desired_count == 0
    )
    error_message = "Meeting services remain hard-zero until their runtime, callback, consent, provider, raw-audio non-persistence, and staged UAT evidence is launch-bound."
  }

  assert {
    condition     = var.meeting_media_desired_count == 0 || local.meeting_media_runtime_packaged
    error_message = "A meeting-media service cannot activate without digest-bound executable-runtime evidence and the reviewed image entrypoint."
  }

  assert {
    condition = !var.meeting_external_provider_egress_enabled || (
      local.meeting_media_runtime_packaged &&
      var.meeting_provider_egress_proxy_origin != "" &&
      var.meeting_provider_egress_proxy_security_group_id != "" &&
      length(var.meeting_approved_provider_hosts) > 0
    )
    error_message = "External meeting providers require the packaged media runtime and an exact private Snowman egress proxy with a non-empty reviewed host allowlist."
  }
}

resource "aws_security_group" "meeting_command" {
  name        = "${local.workload_name}-meeting-command"
  description = "Private meeting-command service; database and AWS control paths only"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "meeting_command_ingress" {
  name        = "${local.workload_name}-meeting-command-ingress"
  description = "PrivateLink and Snowman workforce TLS ingress to meeting commands"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "meeting_media" {
  name        = "${local.workload_name}-meeting-media"
  description = "Private live-media control plane with no direct internet or object-store route"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_vpc_security_group_ingress_rule" "meeting_command_ingress_from_worker" {
  security_group_id            = aws_security_group.meeting_command_ingress.id
  referenced_security_group_id = aws_security_group.worker.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Governed Snowman workforce callers only"
}

resource "aws_vpc_security_group_egress_rule" "meeting_command_ingress_to_service" {
  security_group_id            = aws_security_group.meeting_command_ingress.id
  referenced_security_group_id = aws_security_group.meeting_command.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "meeting_command_from_ingress" {
  security_group_id            = aws_security_group.meeting_command.id
  referenced_security_group_id = aws_security_group.meeting_command_ingress.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "database_from_meeting_command" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.meeting_command.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "meeting_command_to_database" {
  security_group_id            = aws_security_group.meeting_command.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "database_from_meeting_media" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.meeting_media.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "meeting_media_to_database" {
  security_group_id            = aws_security_group.meeting_media.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "meeting_media_from_command" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  security_group_id            = aws_security_group.meeting_media.id
  referenced_security_group_id = aws_security_group.meeting_command.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "Fenced media commands from the meeting-command service only"
}

resource "aws_vpc_security_group_egress_rule" "meeting_command_to_media" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  security_group_id            = aws_security_group.meeting_command.id
  referenced_security_group_id = aws_security_group.meeting_media.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_meeting_services" {
  for_each = {
    command = aws_security_group.meeting_command.id
    media   = aws_security_group.meeting_media.id
  }

  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = each.value
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "meeting_services_to_endpoints" {
  for_each = {
    command = aws_security_group.meeting_command.id
    media   = aws_security_group.meeting_media.id
  }

  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "KMS, Secrets Manager, ECR, ECS, and CloudWatch through private AWS endpoints only"
}

resource "aws_vpc_security_group_egress_rule" "meeting_services_to_dns_udp" {
  for_each = {
    command = aws_security_group.meeting_command.id
    media   = aws_security_group.meeting_media.id
  }

  security_group_id = each.value
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC resolver only"
}

resource "aws_vpc_security_group_egress_rule" "meeting_services_to_dns_tcp" {
  for_each = {
    command = aws_security_group.meeting_command.id
    media   = aws_security_group.meeting_media.id
  }

  security_group_id = each.value
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  description       = "VPC resolver only"
}

# Provider traffic never receives a 0.0.0.0/0 route. When separately approved,
# the media task may reach only the Snowman-owned policy proxy security group.
resource "aws_vpc_security_group_egress_rule" "meeting_media_to_provider_proxy" {
  count = var.meeting_external_provider_egress_enabled ? 1 : 0

  security_group_id            = aws_security_group.meeting_media.id
  referenced_security_group_id = var.meeting_provider_egress_proxy_security_group_id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "Exact private Snowman provider-egress policy proxy only"
}

resource "aws_lb" "meeting_command_private" {
  count = var.meeting_command_private_ingress_enabled ? 1 : 0

  name                                                         = substr("${local.workload_name}-meeting", 0, 32)
  internal                                                     = true
  load_balancer_type                                           = "network"
  subnets                                                      = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
  security_groups                                              = [aws_security_group.meeting_command_ingress.id]
  enforce_security_group_inbound_rules_on_private_link_traffic = "off"
  enable_cross_zone_load_balancing                             = true
  enable_deletion_protection                                   = true
}

resource "aws_lb_target_group" "meeting_command_private" {
  count = var.meeting_command_private_ingress_enabled ? 1 : 0

  name        = substr("${local.workload_name}-meeting", 0, 32)
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

resource "aws_lb_listener" "meeting_command_private" {
  count = var.meeting_command_private_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.meeting_command_private[0].arn
  port              = 443
  protocol          = "TLS"
  certificate_arn   = var.meeting_command_tls_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.meeting_command_private[0].arn
  }
}

resource "aws_vpc_endpoint_service" "meeting_command" {
  count = var.meeting_command_private_ingress_enabled ? 1 : 0

  acceptance_required        = true
  network_load_balancer_arns = [aws_lb.meeting_command_private[0].arn]
  allowed_principals         = sort(tolist(var.meeting_command_consumer_principal_arns))
  private_dns_name           = var.meeting_command_private_dns_name
}

resource "aws_route53_zone" "meeting_command_private" {
  count = var.meeting_command_private_ingress_enabled ? 1 : 0

  name = var.meeting_command_private_dns_name
  vpc { vpc_id = aws_vpc.command_center.id }
}

resource "aws_route53_record" "meeting_command_private" {
  count = var.meeting_command_private_ingress_enabled ? 1 : 0

  zone_id = aws_route53_zone.meeting_command_private[0].zone_id
  name    = var.meeting_command_private_dns_name
  type    = "A"
  alias {
    name                   = aws_lb.meeting_command_private[0].dns_name
    zone_id                = aws_lb.meeting_command_private[0].zone_id
    evaluate_target_health = true
  }
}

resource "aws_kms_key" "meeting_command_receipts" {
  description              = "Snowman meeting-command signed receipts"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_kms_alias" "meeting_command_receipts" {
  name          = "alias/${local.workload_name}-meeting-command-receipts"
  target_key_id = aws_kms_key.meeting_command_receipts.key_id
}

resource "aws_secretsmanager_secret" "meeting_command_runtime" {
  name                    = "/snowman/command-center/${var.environment}/meeting-command/runtime"
  description             = "Dedicated snowman_meeting_control DATABASE_URL; value populated out of band"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "meeting_media_runtime" {
  name                    = "/snowman/command-center/${var.environment}/meeting-media/runtime"
  description             = "Dedicated snowman_meeting_media DATABASE_URL only; provider credentials remain in the separate egress proxy"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_iam_role" "meeting_command_execution" {
  name               = "${local.workload_name}-meeting-command-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "meeting_command_execution" {
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
    sid       = "MeetingCommandLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["meeting-command"].arn}:*"]
  }
  statement {
    sid       = "ExactMeetingCommandRuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.meeting_command_runtime.arn]
  }
  statement {
    sid       = "MeetingCommandRuntimeSecretKey"
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

resource "aws_iam_role_policy" "meeting_command_execution" {
  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.meeting_command_execution.id
  policy = data.aws_iam_policy_document.meeting_command_execution.json
}

resource "aws_iam_role" "meeting_command_task" {
  name               = "${local.workload_name}-meeting-command-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "meeting_command_task" {
  statement {
    sid       = "SignExactMeetingCommandReceipts"
    effect    = "Allow"
    actions   = ["kms:Sign", "kms:GetPublicKey"]
    resources = [aws_kms_key.meeting_command_receipts.arn]
  }
}

resource "aws_iam_role_policy" "meeting_command_task" {
  name   = "sign-exact-meeting-command-receipts"
  role   = aws_iam_role.meeting_command_task.id
  policy = data.aws_iam_policy_document.meeting_command_task.json
}

resource "aws_ecs_task_definition" "meeting_command" {
  family                   = "${local.workload_name}-meeting-command"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.meeting_command_execution.arn
  task_role_arn            = aws_iam_role.meeting_command_task.arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "meeting-command"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    privileged             = false
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-meeting-command-service"]
    stopTimeout            = 60
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    portMappings = [{
      name          = "meeting-command"
      containerPort = 8080
      hostPort      = 8080
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      { name = "SNOWMAN_MEETING_COMMAND_BIND_ADDR", value = "0.0.0.0:8080" },
      { name = "SNOWMAN_MEETING_COMMAND_DATABASE_ROLE", value = "snowman_meeting_control" },
      { name = "SNOWMAN_MEETING_COMMAND_MAX_CONNECTIONS", value = "8" },
      { name = "SNOWMAN_MEETING_COMMAND_NETWORK_POLICY", value = "private-snowman-only" },
      { name = "SNOWMAN_MEETING_COMMAND_PUBLIC_ORIGIN", value = "https://${var.meeting_command_private_dns_name}/" },
      { name = "SNOWMAN_MEETING_COMMAND_RECEIVER_IDENTITY_ID", value = var.meeting_command_receiver_identity_id },
      { name = "SNOWMAN_MEETING_COMMAND_RECEIPT_KEY_ARN", value = aws_kms_key.meeting_command_receipts.arn },
      { name = "NO_PROXY", value = "*" },
    ]
    secrets = [{
      name      = "SNOWMAN_MEETING_COMMAND_DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.meeting_command_runtime.arn}:DATABASE_URL::"
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
        awslogs-group         = aws_cloudwatch_log_group.runtime["meeting-command"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "meeting-command"
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.meeting_command_desired_count == 0
      error_message = "Meeting command remains dormant until exact Analyst caller, restore, isolation, signing, and staged command-replay evidence passes."
    }
  }
}

resource "aws_ecs_service" "meeting_command" {
  name            = "${local.workload_name}-meeting-command"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.meeting_command.arn
  desired_count   = var.meeting_command_desired_count
  launch_type     = "FARGATE"

  enable_execute_command = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  dynamic "load_balancer" {
    for_each = var.meeting_command_private_ingress_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.meeting_command_private[0].arn
      container_name   = "meeting-command"
      container_port   = 8080
    }
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.meeting_command.id]
    assign_public_ip = false
  }

  depends_on = [aws_lb_listener.meeting_command_private]
}

resource "aws_appautoscaling_target" "meeting_command" {
  max_capacity       = 2
  min_capacity       = 0
  resource_id        = "service/${aws_ecs_cluster.command_center.name}/${aws_ecs_service.meeting_command.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "meeting_command_cpu" {
  name               = "${local.workload_name}-meeting-command-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.meeting_command.resource_id
  scalable_dimension = aws_appautoscaling_target.meeting_command.scalable_dimension
  service_namespace  = aws_appautoscaling_target.meeting_command.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

# The provider-neutral media crate is not yet a server binary. These resources
# do not exist until immutable evidence and an exact reviewed entrypoint are
# supplied; default plans therefore cannot pretend the media runtime is usable.
resource "aws_service_discovery_private_dns_namespace" "meeting_media" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  name = local.meeting_media_namespace
  vpc  = aws_vpc.command_center.id
}

resource "aws_service_discovery_service" "meeting_media" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  name = "gateway"
  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.meeting_media[0].id
    dns_records {
      ttl  = 10
      type = "A"
    }
    routing_policy = "MULTIVALUE"
  }
  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_iam_role" "meeting_media_execution" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  name               = "${local.workload_name}-meeting-media-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "meeting_media_execution" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

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
    sid       = "MeetingMediaLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["meeting-media"].arn}:*"]
  }
  statement {
    sid       = "ExactMeetingMediaRuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.meeting_media_runtime.arn]
  }
  statement {
    sid       = "MeetingMediaRuntimeSecretKey"
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

resource "aws_iam_role_policy" "meeting_media_execution" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  name   = "exact-image-secret-and-logs"
  role   = aws_iam_role.meeting_media_execution[0].id
  policy = data.aws_iam_policy_document.meeting_media_execution[0].json
}

resource "aws_ecs_task_definition" "meeting_media" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  family                   = "${local.workload_name}-meeting-media"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.meeting_media_execution[0].arn

  # Deliberately no task role: this runtime has no S3, KMS, queue, model, or
  # credential-discovery authority. Provider credentials stay in the separate
  # Snowman egress proxy and raw audio has no persistence destination.

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "meeting-media"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    privileged             = false
    user                   = "10001"
    entryPoint             = [var.meeting_media_container_entrypoint]
    stopTimeout            = 30
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    portMappings = [{
      name          = "meeting-media"
      containerPort = 8080
      hostPort      = 8080
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      { name = "SNOWMAN_MEETING_MEDIA_BIND_ADDR", value = "0.0.0.0:8080" },
      { name = "SNOWMAN_MEETING_MEDIA_DATABASE_ROLE", value = "snowman_meeting_media" },
      { name = "SNOWMAN_MEETING_MEDIA_MAX_CONNECTIONS", value = "8" },
      { name = "SNOWMAN_MEETING_MEDIA_MAX_INFLIGHT_REQUESTS", value = "32" },
      { name = "SNOWMAN_MEETING_MEDIA_NETWORK_POLICY", value = "private-snowman-only" },
      { name = "SNOWMAN_MEETING_MEDIA_RAW_AUDIO_RETENTION", value = "none" },
      { name = "SNOWMAN_MEETING_MEDIA_PROVIDER_EGRESS_ENABLED", value = tostring(var.meeting_external_provider_egress_enabled) },
      { name = "SNOWMAN_MEETING_MEDIA_CALLBACK_INGRESS_ENABLED", value = "false" },
      { name = "SNOWMAN_MEETING_MEDIA_PROVIDER_EGRESS_PROXY_ORIGIN", value = var.meeting_provider_egress_proxy_origin },
      { name = "SNOWMAN_MEETING_MEDIA_APPROVED_PROVIDER_HOSTS", value = join(",", sort(tolist(var.meeting_approved_provider_hosts))) },
      { name = "HTTP_PROXY", value = "" },
      { name = "HTTPS_PROXY", value = "" },
      { name = "NO_PROXY", value = "*" },
    ]
    secrets = [{
      name      = "SNOWMAN_MEETING_MEDIA_DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.meeting_media_runtime.arn}:DATABASE_URL::"
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
        awslogs-group         = aws_cloudwatch_log_group.runtime["meeting-media"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "meeting-media"
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.meeting_media_desired_count == 0
      error_message = "Meeting media remains dormant until callbacks, consent, provider egress, non-persistence, kill switches, and staged UAT pass."
    }
  }
}

resource "aws_ecs_service" "meeting_media" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  name            = "${local.workload_name}-meeting-media"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.meeting_media[0].arn
  desired_count   = var.meeting_media_desired_count
  launch_type     = "FARGATE"

  enable_execute_command = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.meeting_media.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.meeting_media[0].arn
  }
}

resource "aws_appautoscaling_target" "meeting_media" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  max_capacity       = 4
  min_capacity       = 0
  resource_id        = "service/${aws_ecs_cluster.command_center.name}/${aws_ecs_service.meeting_media[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "meeting_media_cpu" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  name               = "${local.workload_name}-meeting-media-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.meeting_media[0].resource_id
  scalable_dimension = aws_appautoscaling_target.meeting_media[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.meeting_media[0].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "meeting_command_running_tasks" {
  alarm_name          = "${local.workload_name}-meeting-command-running-tasks"
  alarm_description   = "Private meeting-command service below its explicitly requested task count"
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = var.meeting_command_desired_count
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = var.meeting_command_desired_count == 0 ? "notBreaching" : "breaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.command_center.name
    ServiceName = aws_ecs_service.meeting_command.name
  }
}

resource "aws_cloudwatch_metric_alarm" "meeting_media_running_tasks" {
  count = local.meeting_media_runtime_packaged ? 1 : 0

  alarm_name          = "${local.workload_name}-meeting-media-running-tasks"
  alarm_description   = "Private meeting-media service below its explicitly requested task count"
  namespace           = "ECS/ContainerInsights"
  metric_name         = "RunningTaskCount"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = var.meeting_media_desired_count
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = var.meeting_media_desired_count == 0 ? "notBreaching" : "breaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]
  dimensions = {
    ClusterName = aws_ecs_cluster.command_center.name
    ServiceName = aws_ecs_service.meeting_media[0].name
  }
}
