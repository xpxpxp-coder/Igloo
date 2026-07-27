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

variable "provider_egress_inspected_network_enabled" {
  description = "Build the dedicated provider-only AWS Network Firewall/NAT path. False leaves no provider internet route."
  type        = bool
  default     = false
}

variable "provider_egress_network_topology" {
  description = "Explicit cost/availability choice: one AZ for dormant staging or three independent AZ paths for production HA."
  type        = string
  default     = "single_az_cost_optimized"
  validation {
    condition     = contains(["single_az_cost_optimized", "three_az_ha"], var.provider_egress_network_topology)
    error_message = "provider_egress_network_topology must be single_az_cost_optimized or three_az_ha."
  }
}

variable "provider_egress_elevenlabs_enabled" {
  description = "Adds only api.elevenlabs.io to the inspected domain rules after optional TTS approval."
  type        = bool
  default     = false
}

variable "provider_egress_workload_subnet_cidrs" {
  description = "Three provider-only workload CIDRs; no other Snowman workload receives their firewall route."
  type        = list(string)
  default     = ["10.72.48.0/24", "10.72.49.0/24", "10.72.50.0/24"]
  validation {
    condition     = length(var.provider_egress_workload_subnet_cidrs) == 3 && alltrue([for cidr in var.provider_egress_workload_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "provider_egress_workload_subnet_cidrs must contain three valid IPv4 CIDRs."
  }
}

variable "provider_egress_firewall_subnet_cidrs" {
  description = "Three dedicated Network Firewall endpoint CIDRs, separate from workloads, data, and public NAT subnets."
  type        = list(string)
  default     = ["10.72.64.0/28", "10.72.64.16/28", "10.72.64.32/28"]
  validation {
    condition     = length(var.provider_egress_firewall_subnet_cidrs) == 3 && alltrue([for cidr in var.provider_egress_firewall_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "provider_egress_firewall_subnet_cidrs must contain three valid IPv4 CIDRs."
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
  provider_egress_approved_domains = concat(
    ["api.twilio.com", "api.openai.com"],
    var.provider_egress_elevenlabs_enabled ? ["api.elevenlabs.io"] : [],
  )
  provider_egress_inspected_network_packaged = (
    var.provider_egress_inspected_network_enabled && local.provider_egress_packaged
  )
  provider_egress_inspection_slots = !local.provider_egress_inspected_network_packaged ? {} : (
    var.provider_egress_network_topology == "three_az_ha" ? local.subnet_slots : {
      "0" = local.subnet_slots["0"]
    }
  )
  provider_egress_firewall_endpoints_by_az = local.provider_egress_inspected_network_packaged ? {
    for state in aws_networkfirewall_firewall.provider_egress[0].firewall_status[0].sync_states :
    state.availability_zone => state.attachment[0].endpoint_id
  } : {}
}

check "provider_egress_activation_boundary" {
  assert {
    condition = !var.provider_egress_inspected_network_enabled || (
      local.provider_egress_packaged &&
      var.provider_egress_inspected_egress_evidence_sha256 != ""
    )
    error_message = "The inspected provider network may be built only with packaged runtime policy and immutable inspection evidence."
  }
  assert {
    condition = length(setintersection(
      toset(var.provider_egress_workload_subnet_cidrs),
      toset(concat(var.public_subnet_cidrs, var.private_subnet_cidrs, var.data_subnet_cidrs, var.provider_egress_firewall_subnet_cidrs)),
      )) == 0 && length(setintersection(
      toset(var.provider_egress_firewall_subnet_cidrs),
      toset(concat(var.public_subnet_cidrs, var.private_subnet_cidrs, var.data_subnet_cidrs)),
    )) == 0
    error_message = "Provider workload and firewall subnets must be distinct from every existing Snowman subnet."
  }
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
      alltrue([for route in try(local.provider_egress_policy.routes, []) : (
        can(regex("^https://(?:api[.]twilio[.]com|api[.]openai[.]com)/", route.endpoint)) ||
        (var.provider_egress_elevenlabs_enabled && can(regex("^https://api[.]elevenlabs[.]io/", route.endpoint)))
      )])
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
  cidr_ipv4         = "${cidrhost(var.vpc_cidr, 2)}/32"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC resolver only; mixed/private answers are denied in-process"
}

resource "aws_vpc_security_group_egress_rule" "provider_egress_dns_tcp" {
  count = local.provider_egress_packaged ? 1 : 0

  security_group_id = aws_security_group.provider_egress[0].id
  cidr_ipv4         = "${cidrhost(var.vpc_cidr, 2)}/32"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
}

# The only broad-address security-group rule is bound to the dedicated provider
# subnets whose sole default route is a Network Firewall endpoint. The stateful
# engine then permits exact TLS SNI/HTTP Host domains and drops everything else.
resource "aws_vpc_security_group_egress_rule" "provider_egress_to_inspected_https" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  security_group_id = aws_security_group.provider_egress[0].id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS only through the dedicated provider Network Firewall route"
}

resource "aws_subnet" "provider_egress_workload" {
  for_each = local.provider_egress_inspection_slots

  vpc_id                  = aws_vpc.command_center.id
  availability_zone       = each.value.zone
  cidr_block              = var.provider_egress_workload_subnet_cidrs[tonumber(each.key)]
  map_public_ip_on_launch = false

  tags = {
    Name          = "${local.workload_name}-provider-egress-${each.value.zone}"
    Tier          = "provider-egress-only"
    InternetRoute = "network-firewall-only"
  }
}

resource "aws_subnet" "provider_egress_firewall" {
  for_each = local.provider_egress_inspection_slots

  vpc_id                  = aws_vpc.command_center.id
  availability_zone       = each.value.zone
  cidr_block              = var.provider_egress_firewall_subnet_cidrs[tonumber(each.key)]
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.workload_name}-provider-firewall-${each.value.zone}"
    Tier = "network-firewall"
  }
}

resource "aws_eip" "provider_egress_nat" {
  for_each = local.provider_egress_inspection_slots

  domain = "vpc"
  tags   = { Name = "${local.workload_name}-provider-nat-${each.value.zone}" }
}

resource "aws_nat_gateway" "provider_egress" {
  for_each = local.provider_egress_inspection_slots

  allocation_id     = aws_eip.provider_egress_nat[each.key].id
  subnet_id         = aws_subnet.public[each.key].id
  connectivity_type = "public"

  tags       = { Name = "${local.workload_name}-provider-nat-${each.value.zone}" }
  depends_on = [aws_internet_gateway.edge]
}

resource "aws_cloudwatch_log_group" "provider_egress_firewall_alert" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  name              = "/snowman/command-center/${var.environment}/provider-egress/firewall/alert"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_cloudwatch_log_group" "provider_egress_firewall_flow" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  name              = "/snowman/command-center/${var.environment}/provider-egress/firewall/flow"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_networkfirewall_rule_group" "provider_egress_domains" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  name        = "${local.workload_name}-provider-domains"
  description = "Exact Snowman-approved TLS SNI and HTTP Host values; all other external traffic is dropped"
  type        = "STATEFUL"
  capacity    = 100

  encryption_configuration {
    key_id = aws_kms_key.data.arn
    type   = "CUSTOMER_KMS"
  }

  rule_group {
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set {
          definition = [for key in sort(keys(local.provider_egress_inspection_slots)) : var.provider_egress_workload_subnet_cidrs[tonumber(key)]]
        }
      }
    }
    rules_source {
      rules_string = join("\n", concat(
        [for index, domain in local.provider_egress_approved_domains : "pass tls $HOME_NET any -> $EXTERNAL_NET 443 (flow:to_server,established; tls.sni; content:\"${domain}\"; startswith; endswith; nocase; msg:\"Snowman approved TLS SNI ${domain}\"; sid:${1000001 + index}; rev:1;)"],
        [for index, domain in local.provider_egress_approved_domains : "pass http $HOME_NET any -> $EXTERNAL_NET 80 (flow:to_server,established; http.host; content:\"${domain}\"; startswith; endswith; nocase; msg:\"Snowman approved HTTP Host ${domain}\"; sid:${1000101 + index}; rev:1;)"],
        [
          "drop ip $HOME_NET any -> $EXTERNAL_NET any (msg:\"Snowman provider egress default deny\"; sid:1000201; rev:1;)",
        ],
      ))
    }
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "provider_egress" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  name = "${local.workload_name}-provider-egress"
  encryption_configuration {
    key_id = aws_kms_key.data.arn
    type   = "CUSTOMER_KMS"
  }
  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    stateful_default_actions           = ["aws:drop_strict"]
    stateful_engine_options {
      rule_order              = "STRICT_ORDER"
      stream_exception_policy = "DROP"
    }
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.provider_egress_domains[0].arn
      priority     = 10
    }
  }
}

resource "aws_networkfirewall_firewall" "provider_egress" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  name                = "${local.workload_name}-provider-egress"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.provider_egress[0].arn
  vpc_id              = aws_vpc.command_center.id

  dynamic "subnet_mapping" {
    for_each = aws_subnet.provider_egress_firewall
    content {
      subnet_id = subnet_mapping.value.id
    }
  }

  delete_protection                 = true
  firewall_policy_change_protection = true
  subnet_change_protection          = true
  encryption_configuration {
    key_id = aws_kms_key.data.arn
    type   = "CUSTOMER_KMS"
  }
}

resource "aws_networkfirewall_logging_configuration" "provider_egress" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  firewall_arn = aws_networkfirewall_firewall.provider_egress[0].arn
  logging_configuration {
    log_destination_config {
      log_destination      = { logGroup = aws_cloudwatch_log_group.provider_egress_firewall_alert[0].name }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }
    log_destination_config {
      log_destination      = { logGroup = aws_cloudwatch_log_group.provider_egress_firewall_flow[0].name }
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
    }
  }
}

resource "aws_route_table" "provider_egress_workload" {
  for_each = local.provider_egress_inspection_slots

  vpc_id = aws_vpc.command_center.id
  tags   = { Name = "${local.workload_name}-provider-workload-${each.value.zone}", Bypass = "denied" }
}

resource "aws_route_table_association" "provider_egress_workload" {
  for_each = local.provider_egress_inspection_slots

  subnet_id      = aws_subnet.provider_egress_workload[each.key].id
  route_table_id = aws_route_table.provider_egress_workload[each.key].id
}

resource "aws_route" "provider_egress_workload_to_firewall" {
  for_each = local.provider_egress_inspection_slots

  route_table_id         = aws_route_table.provider_egress_workload[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = local.provider_egress_firewall_endpoints_by_az[each.value.zone]
}

resource "aws_route_table" "provider_egress_firewall" {
  for_each = local.provider_egress_inspection_slots

  vpc_id = aws_vpc.command_center.id
  tags   = { Name = "${local.workload_name}-provider-firewall-${each.value.zone}" }
}

resource "aws_route_table_association" "provider_egress_firewall" {
  for_each = local.provider_egress_inspection_slots

  subnet_id      = aws_subnet.provider_egress_firewall[each.key].id
  route_table_id = aws_route_table.provider_egress_firewall[each.key].id
}

resource "aws_route" "provider_egress_firewall_to_nat" {
  for_each = local.provider_egress_inspection_slots

  route_table_id         = aws_route_table.provider_egress_firewall[each.key].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.provider_egress[each.key].id
}

# The existing public route table is ingress-only for all other workloads. These
# exact return routes send only provider-subnet traffic back through the same
# AZ firewall endpoint before the dedicated NAT can deliver it to the task.
resource "aws_route" "provider_egress_nat_return_to_firewall" {
  for_each = local.provider_egress_inspection_slots

  route_table_id         = aws_route_table.public.id
  destination_cidr_block = var.provider_egress_workload_subnet_cidrs[tonumber(each.key)]
  vpc_endpoint_id        = local.provider_egress_firewall_endpoints_by_az[each.value.zone]
}

resource "aws_cloudwatch_log_metric_filter" "provider_egress_firewall_denied" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  name           = "${local.workload_name}-provider-egress-denied"
  log_group_name = aws_cloudwatch_log_group.provider_egress_firewall_alert[0].name
  pattern        = "{ $.event.event_type = \"alert\" }"
  metric_transformation {
    name      = "DeniedFlows"
    namespace = "Snowman/ProviderEgress"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "provider_egress_firewall_denied" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  alarm_name          = "${local.workload_name}-provider-egress-denied"
  alarm_description   = "Provider-only egress attempted a non-approved TLS SNI, HTTP Host, protocol, or destination."
  namespace           = "Snowman/ProviderEgress"
  metric_name         = "DeniedFlows"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.operations.arn]
  ok_actions          = [aws_sns_topic.operations.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.provider_egress_firewall_denied]
}

resource "aws_cloudwatch_metric_alarm" "provider_egress_firewall_log_delivery" {
  count = local.provider_egress_inspected_network_packaged ? 1 : 0

  alarm_name          = "${local.workload_name}-provider-egress-firewall-log-delivery"
  alarm_description   = "CloudWatch could not deliver provider-egress Network Firewall evidence."
  namespace           = "AWS/Logs"
  metric_name         = "DeliveryErrors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions = {
    LogGroupName = aws_cloudwatch_log_group.provider_egress_firewall_alert[0].name
  }
  alarm_actions = [aws_sns_topic.operations.arn]
  ok_actions    = [aws_sns_topic.operations.arn]
}

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
    resources = [aws_secretsmanager_secret.provider_egress_runtime.arn]
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
      valueFrom = "${aws_secretsmanager_secret.provider_egress_runtime.arn}:DATABASE_URL::"
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
    subnets = local.provider_egress_inspected_network_packaged ? [
      for key in sort(keys(aws_subnet.provider_egress_workload)) : aws_subnet.provider_egress_workload[key].id
    ] : [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id]
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
    inspected_network_built   = local.provider_egress_inspected_network_packaged
    network_topology          = var.provider_egress_network_topology
    approved_provider_domains = local.provider_egress_approved_domains
    network_firewall_arn      = try(aws_networkfirewall_firewall.provider_egress[0].arn, null)
  }
}
