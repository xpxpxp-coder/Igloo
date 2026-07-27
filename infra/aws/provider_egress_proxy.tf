# Dormant AWS-native provider-egress boundary. This file is intentionally
# self-contained: it does not widen any existing meeting or orchestration role.

variable "provider_egress_runtime_evidence_sha256" {
  description = "Digest of reviewed runtime, transport, replay, and non-persistence evidence."
  type        = string
  default     = ""
  validation {
    condition     = var.provider_egress_runtime_evidence_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.provider_egress_runtime_evidence_sha256))
    error_message = "provider_egress_runtime_evidence_sha256 must be empty or a lowercase SHA-256 digest."
  }
}

variable "provider_egress_policy_json" {
  description = "Non-secret, operations-sealed route/principal policy consumed by the runtime."
  type        = string
  default     = ""
  validation {
    condition     = var.provider_egress_policy_json == "" || can(jsondecode(var.provider_egress_policy_json))
    error_message = "provider_egress_policy_json must be empty or valid JSON."
  }
}

variable "provider_egress_workload_kms_key_arns" {
  description = "Exact same-account asymmetric KMS keys permitted to authenticate callers."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for arn in var.provider_egress_workload_kms_key_arns :
      can(regex("^arn:aws(?:-[a-z]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$", arn))
    ])
    error_message = "Provider-egress caller keys must be exact asymmetric KMS key ARNs."
  }
}

variable "provider_egress_provider_secret_arns" {
  description = "Exact Snowman-owned provider credential secrets readable only by the proxy task."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for arn in var.provider_egress_provider_secret_arns :
      can(regex("^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:snowman-[A-Za-z0-9/_+=.@-]+$", arn))
    ])
    error_message = "Provider credentials must be exact Snowman-named Secrets Manager ARNs."
  }
}

variable "provider_egress_tls_certificate_arn" {
  description = "Local ACM certificate for optional private TLS ingress."
  type        = string
  default     = ""
}

variable "provider_egress_private_ingress_enabled" {
  description = "Creates the private TLS NLB only after staged ingress evidence exists."
  type        = bool
  default     = false
}

variable "provider_egress_inspected_egress_evidence_sha256" {
  description = "Evidence for an exact provider-domain AWS Network Firewall or Snowman Cloudflare egress path."
  type        = string
  default     = ""
  validation {
    condition     = var.provider_egress_inspected_egress_evidence_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.provider_egress_inspected_egress_evidence_sha256))
    error_message = "provider_egress_inspected_egress_evidence_sha256 must be empty or a lowercase SHA-256 digest."
  }
}

variable "provider_egress_desired_count" {
  description = "Hard dormant until provider/network/recovery UAT is launch-bound."
  type        = number
  default     = 0
  validation {
    condition     = var.provider_egress_desired_count == 0
    error_message = "provider_egress_desired_count remains hard-zero until the production activation gate is deliberately revised."
  }
}

locals {
  provider_egress_packaged = (
    var.provider_egress_runtime_evidence_sha256 != "" &&
    var.provider_egress_policy_json != "" &&
    length(var.provider_egress_workload_kms_key_arns) > 0 &&
    length(var.provider_egress_provider_secret_arns) > 0
  )
  provider_egress_policy = var.provider_egress_policy_json == "" ? null : jsondecode(var.provider_egress_policy_json)
}

check "provider_egress_activation_boundary" {
  assert {
    condition = var.provider_egress_desired_count == 0 || (
      var.provider_egress_inspected_egress_evidence_sha256 != ""
    )
    error_message = "Provider egress stays dormant and unroutable until exact-domain inspected-egress evidence exists."
  }
  assert {
    condition = !local.provider_egress_packaged || (
      alltrue([for arn in var.provider_egress_workload_kms_key_arns : split(":", arn)[4] == var.expected_workload_account_id]) &&
      alltrue([for arn in var.provider_egress_provider_secret_arns : split(":", arn)[4] == var.expected_workload_account_id]) &&
      alltrue([for principal in try(local.provider_egress_policy.principals, []) : contains(tolist(var.provider_egress_workload_kms_key_arns), principal.kms_key_arn)]) &&
      alltrue([for route in try(local.provider_egress_policy.routes, []) : contains(tolist(var.provider_egress_provider_secret_arns), route.secret_arn)]) &&
      alltrue([for route in try(local.provider_egress_policy.routes, []) : can(regex("^https://(?:api[.]twilio[.]com|api[.]openai[.]com|api[.]elevenlabs[.]io)/", route.endpoint))])
    )
    error_message = "Provider policy may reference only exact same-account caller keys, Snowman provider secrets, and approved provider hosts."
  }
  assert {
    condition = !var.provider_egress_private_ingress_enabled || (
      local.provider_egress_packaged &&
      can(regex("^arn:aws(?:-[a-z]+)?:acm:[a-z0-9-]+:[0-9]{12}:certificate/[0-9a-fA-F-]{36}$", var.provider_egress_tls_certificate_arn)) &&
      split(":", var.provider_egress_tls_certificate_arn)[4] == var.expected_workload_account_id
    )
    error_message = "Private ingress requires packaged evidence and an exact same-account ACM certificate."
  }
}

resource "aws_secretsmanager_secret" "provider_egress_runtime" {
  count = local.provider_egress_packaged ? 1 : 0

  name                    = "/snowman/command-center/${var.environment}/provider-egress-runtime"
  description             = "Dedicated provider-egress database URL populated only by governed bootstrap"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 30
}

resource "aws_cloudwatch_log_group" "provider_egress" {
  count = local.provider_egress_packaged ? 1 : 0

  name              = "/snowman/command-center/${var.environment}/provider-egress"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_security_group" "provider_egress" {
  count = local.provider_egress_packaged ? 1 : 0

  name        = "${local.workload_name}-provider-egress"
  description = "Only Snowman media ingress; exact provider HTTPS egress is enforced again in-process"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "provider_egress_ingress" {
  count = var.provider_egress_private_ingress_enabled ? 1 : 0

  name        = "${local.workload_name}-provider-egress-ingress"
  description = "Private TLS ingress from Snowman meeting media only"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_vpc_security_group_ingress_rule" "provider_egress_ingress_from_media" {
  count = var.provider_egress_private_ingress_enabled ? 1 : 0

  security_group_id            = aws_security_group.provider_egress_ingress[0].id
  referenced_security_group_id = aws_security_group.meeting_media.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "provider_egress_ingress_to_task" {
  count = var.provider_egress_private_ingress_enabled ? 1 : 0

  security_group_id            = aws_security_group.provider_egress_ingress[0].id
  referenced_security_group_id = aws_security_group.provider_egress[0].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "provider_egress_from_ingress" {
  count = var.provider_egress_private_ingress_enabled ? 1 : 0

  security_group_id            = aws_security_group.provider_egress[0].id
  referenced_security_group_id = aws_security_group.provider_egress_ingress[0].id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "database_from_provider_egress" {
  count = local.provider_egress_packaged ? 1 : 0

  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.provider_egress[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "provider_egress_to_database" {
  count = local.provider_egress_packaged ? 1 : 0

  security_group_id            = aws_security_group.provider_egress[0].id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_provider_egress" {
  count = local.provider_egress_packaged ? 1 : 0

  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = aws_security_group.provider_egress[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "provider_egress_to_endpoints" {
  count = local.provider_egress_packaged ? 1 : 0

  security_group_id            = aws_security_group.provider_egress[0].id
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "provider_egress_dns_udp" {
  count = local.provider_egress_packaged ? 1 : 0

  security_group_id = aws_security_group.provider_egress[0].id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC resolver only; mixed/private answers are denied in-process"
}

resource "aws_vpc_security_group_egress_rule" "provider_egress_dns_tcp" {
  count = local.provider_egress_packaged ? 1 : 0

  security_group_id = aws_security_group.provider_egress[0].id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
}

# No public HTTPS security-group rule or route is created here. Activation must
# add a reviewed AWS Network Firewall domain-list route or Snowman Cloudflare
# egress control in a separate evidence-bound change. Application host sealing
# remains defense in depth and is not represented as network-exact enforcement.

resource "aws_iam_role" "provider_egress_execution" {
  count = local.provider_egress_packaged ? 1 : 0

  name               = "${local.workload_name}-provider-egress-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "provider_egress_execution" {
  count = local.provider_egress_packaged ? 1 : 0

  statement {
    sid       = "EcrAuthorization"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid    = "ExactImage"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.command_center.arn]
  }
  statement {
    sid       = "RuntimeSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.provider_egress_runtime[0].arn]
  }
  statement {
    sid       = "RuntimeSecretKms"
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
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.provider_egress[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "provider_egress_execution" {
  count = local.provider_egress_packaged ? 1 : 0

  name   = "exact-image-runtime-secret-and-logs"
  role   = aws_iam_role.provider_egress_execution[0].id
  policy = data.aws_iam_policy_document.provider_egress_execution[0].json
}

resource "aws_iam_role" "provider_egress_task" {
  count = local.provider_egress_packaged ? 1 : 0

  name               = "${local.workload_name}-provider-egress-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "provider_egress_task" {
  count = local.provider_egress_packaged ? 1 : 0

  statement {
    sid       = "VerifyExactCallerKeys"
    effect    = "Allow"
    actions   = ["kms:Verify"]
    resources = sort(tolist(var.provider_egress_workload_kms_key_arns))
  }
  statement {
    sid       = "ReadExactProviderSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = sort(tolist(var.provider_egress_provider_secret_arns))
  }
}

resource "aws_iam_role_policy" "provider_egress_task" {
  count = local.provider_egress_packaged ? 1 : 0

  name   = "verify-callers-and-read-exact-provider-secrets"
  role   = aws_iam_role.provider_egress_task[0].id
  policy = data.aws_iam_policy_document.provider_egress_task[0].json
}

resource "aws_ecs_task_definition" "provider_egress" {
  count = local.provider_egress_packaged ? 1 : 0

  family                   = "${local.workload_name}-provider-egress"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.provider_egress_execution[0].arn
  task_role_arn            = aws_iam_role.provider_egress_task[0].arn

  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "provider-egress"
    image                  = var.container_image
    essential              = true
    readonlyRootFilesystem = true
    privileged             = false
    user                   = "1000"
    entryPoint             = ["/usr/local/bin/snowman-provider-egress-proxy"]
    stopTimeout            = 60
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    portMappings = [{
      name          = "provider-egress"
      containerPort = 8443
      hostPort      = 8443
      protocol      = "tcp"
      appProtocol   = "http"
    }]
    environment = [
      { name = "SNOWMAN_PROVIDER_EGRESS_BIND_ADDR", value = "0.0.0.0:8443" },
      { name = "SNOWMAN_PROVIDER_EGRESS_DATABASE_ROLE", value = "snowman_provider_egress" },
      { name = "SNOWMAN_PROVIDER_EGRESS_AWS_ACCOUNT_ID", value = var.expected_workload_account_id },
      { name = "SNOWMAN_PROVIDER_EGRESS_NETWORK_POLICY", value = "private-snowman-provider-only" },
      { name = "SNOWMAN_PROVIDER_EGRESS_POLICY_JSON", value = var.provider_egress_policy_json },
      { name = "HTTP_PROXY", value = "" },
      { name = "HTTPS_PROXY", value = "" },
      { name = "NO_PROXY", value = "*" },
      { name = "RUST_LOG", value = "snowman_provider_egress_proxy=info" },
    ]
    secrets = [{
      name      = "SNOWMAN_PROVIDER_EGRESS_DATABASE_URL"
      valueFrom = "${aws_secretsmanager_secret.provider_egress_runtime[0].arn}:DATABASE_URL::"
    }]
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
        awslogs-group         = aws_cloudwatch_log_group.provider_egress[0].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "provider-egress"
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.provider_egress_desired_count == 0
      error_message = "Provider egress remains dormant until staged provider and network-denial evidence passes."
    }
  }
}

resource "aws_ecs_service" "provider_egress" {
  count = local.provider_egress_packaged ? 1 : 0

  name            = "${local.workload_name}-provider-egress"
  cluster         = aws_ecs_cluster.command_center.id
  task_definition = aws_ecs_task_definition.provider_egress[0].arn
  desired_count   = var.provider_egress_desired_count
  launch_type     = "FARGATE"

  enable_execute_command = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
    security_groups  = [aws_security_group.provider_egress[0].id]
    assign_public_ip = false
  }

  dynamic "load_balancer" {
    for_each = var.provider_egress_private_ingress_enabled ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.provider_egress[0].arn
      container_name   = "provider-egress"
      container_port   = 8443
    }
  }
}

resource "aws_lb" "provider_egress" {
  count = var.provider_egress_private_ingress_enabled ? 1 : 0

  name                                                         = substr("${local.workload_name}-egress", 0, 32)
  internal                                                     = true
  load_balancer_type                                           = "network"
  subnets                                                      = [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
  security_groups                                              = [aws_security_group.provider_egress_ingress[0].id]
  enforce_security_group_inbound_rules_on_private_link_traffic = "on"
  enable_cross_zone_load_balancing                             = true
  enable_deletion_protection                                   = true
}

resource "aws_lb_target_group" "provider_egress" {
  count = var.provider_egress_private_ingress_enabled ? 1 : 0

  name        = substr("${local.workload_name}-egress", 0, 32)
  port        = 8443
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.command_center.id

  deregistration_delay = 30
  health_check {
    enabled  = true
    protocol = "HTTP"
    path     = "/_readiness"
    port     = "traffic-port"
    matcher  = "200-299"
  }
}

resource "aws_lb_listener" "provider_egress" {
  count = var.provider_egress_private_ingress_enabled ? 1 : 0

  load_balancer_arn = aws_lb.provider_egress[0].arn
  port              = 8443
  protocol          = "TLS"
  certificate_arn   = var.provider_egress_tls_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.provider_egress[0].arn
  }
}

output "provider_egress_activation_boundary" {
  description = "Dormant provider-egress evidence and private ingress coordinates."
  value = {
    packaged                  = local.provider_egress_packaged
    desired_count             = var.provider_egress_desired_count
    security_group_id         = try(aws_security_group.provider_egress[0].id, null)
    private_load_balancer_dns = try(aws_lb.provider_egress[0].dns_name, null)
    inspected_egress_evidence = var.provider_egress_inspected_egress_evidence_sha256
    runtime_evidence_sha256   = var.provider_egress_runtime_evidence_sha256
  }
}
