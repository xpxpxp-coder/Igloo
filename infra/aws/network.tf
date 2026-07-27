locals {
  subnet_slots = {
    for index, zone in var.availability_zones : tostring(index) => {
      zone         = zone
      public_cidr  = var.public_subnet_cidrs[index]
      private_cidr = var.private_subnet_cidrs[index]
      data_cidr    = var.data_subnet_cidrs[index]
    }
  }
  interface_endpoint_services = toset([
    "ecr.api",
    "ecr.dkr",
    "logs",
    "kms",
    "secretsmanager",
    "sts",
    "ssm",
    "ssmmessages",
    "sagemaker.runtime",
  ])
}

resource "aws_vpc" "command_center" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = local.workload_name }
}

resource "aws_internet_gateway" "edge" {
  vpc_id = aws_vpc.command_center.id
  tags   = { Name = "${local.workload_name}-edge" }
}

resource "aws_subnet" "public" {
  for_each = local.subnet_slots

  vpc_id                  = aws_vpc.command_center.id
  availability_zone       = each.value.zone
  cidr_block              = each.value.public_cidr
  map_public_ip_on_launch = false

  tags = { Name = "${local.workload_name}-public-${each.value.zone}", Tier = "edge" }
}

resource "aws_subnet" "private" {
  for_each = local.subnet_slots

  vpc_id                  = aws_vpc.command_center.id
  availability_zone       = each.value.zone
  cidr_block              = each.value.private_cidr
  map_public_ip_on_launch = false

  tags = { Name = "${local.workload_name}-private-${each.value.zone}", Tier = "service" }
}

resource "aws_subnet" "data" {
  for_each = local.subnet_slots

  vpc_id                  = aws_vpc.command_center.id
  availability_zone       = each.value.zone
  cidr_block              = each.value.data_cidr
  map_public_ip_on_launch = false

  tags = { Name = "${local.workload_name}-data-${each.value.zone}", Tier = "data" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.command_center.id
  tags   = { Name = "${local.workload_name}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.edge.id
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  for_each = local.subnet_slots

  vpc_id = aws_vpc.command_center.id
  tags   = { Name = "${local.workload_name}-private-${each.value.zone}", InternetRoute = "none" }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

resource "aws_route_table" "data" {
  for_each = local.subnet_slots

  vpc_id = aws_vpc.command_center.id
  tags   = { Name = "${local.workload_name}-data-${each.value.zone}", InternetRoute = "none" }
}

resource "aws_route_table_association" "data" {
  for_each = aws_subnet.data

  subnet_id      = each.value.id
  route_table_id = aws_route_table.data[each.key].id
}

resource "aws_security_group" "edge" {
  name        = "${local.workload_name}-edge"
  description = "Cloudflare-only ingress to the public Snowman load balancer"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_vpc_security_group_ingress_rule" "edge_from_cloudflare" {
  for_each = var.cloudflare_origin_ipv4_cidrs

  security_group_id = aws_security_group.edge.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Reviewed Cloudflare origin range"
}

resource "aws_security_group" "relay" {
  name        = "${local.workload_name}-relay"
  description = "Snowman relay and private integration API"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "worker" {
  name        = "${local.workload_name}-worker"
  description = "Capability-scoped Snowman workforce workers"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "agent_executor" {
  name        = "${local.workload_name}-agent-executor"
  description = "One-shot Snowman ACP sandboxes with private, deny-by-default egress"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "agent_endpoints" {
  name        = "${local.workload_name}-agent-endpoints"
  description = "Only ECR image-pull and CloudWatch log endpoints for agent sandboxes"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "agent_broker" {
  name        = "${local.workload_name}-agent-broker"
  description = "Purpose-specific broker for one-shot Snowman agent jobs"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "scheduler" {
  name        = "${local.workload_name}-scheduler"
  description = "Deadline and lease maintenance only; no Analyst or model route"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "trigger" {
  name        = "${local.workload_name}-trigger"
  description = "Recurring proposal trigger only; no Analyst or model route"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "reminder" {
  name        = "${local.workload_name}-reminder"
  description = "Fixed Snowman-local reminder delivery only; no Analyst or model route"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "workforce_ingress" {
  name        = "${local.workload_name}-workforce-ingress"
  description = "Private TLS ingress for Snowman workforce service identities"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "model_gateway" {
  name        = "${local.workload_name}-model-gateway"
  description = "Snowman-only model policy gateway"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "inference" {
  name        = "${local.workload_name}-inference"
  description = "Snowman-hosted model inference fleet"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "database" {
  name        = "${local.workload_name}-postgres"
  description = "Tenant-isolated Command Center PostgreSQL"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "valkey" {
  name        = "${local.workload_name}-valkey"
  description = "Tenant-isolated Command Center Valkey"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_security_group" "endpoints" {
  name        = "${local.workload_name}-endpoints"
  description = "Private AWS interface endpoints"
  vpc_id      = aws_vpc.command_center.id
}

resource "aws_vpc_security_group_ingress_rule" "relay_from_edge" {
  security_group_id            = aws_security_group.relay.id
  referenced_security_group_id = aws_security_group.edge.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "edge_to_relay" {
  security_group_id            = aws_security_group.edge.id
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "relay_health_from_edge" {
  security_group_id            = aws_security_group.relay.id
  referenced_security_group_id = aws_security_group.edge.id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
  description                  = "ALB readiness probes only"
}

resource "aws_vpc_security_group_egress_rule" "edge_to_relay_health" {
  security_group_id            = aws_security_group.edge.id
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
  description                  = "ALB readiness probes only"
}

resource "aws_vpc_security_group_ingress_rule" "workforce_ingress_from_services" {
  for_each = {
    worker    = aws_security_group.worker.id
    scheduler = aws_security_group.scheduler.id
    trigger   = aws_security_group.trigger.id
    reminder  = aws_security_group.reminder.id
  }

  security_group_id            = aws_security_group.workforce_ingress.id
  referenced_security_group_id = each.value
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "services_to_workforce_ingress" {
  for_each = {
    worker    = aws_security_group.worker.id
    scheduler = aws_security_group.scheduler.id
    trigger   = aws_security_group.trigger.id
    reminder  = aws_security_group.reminder.id
  }

  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.workforce_ingress.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "relay_from_workforce_ingress" {
  security_group_id            = aws_security_group.relay.id
  referenced_security_group_id = aws_security_group.workforce_ingress.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "workforce_ingress_to_relay" {
  security_group_id            = aws_security_group.workforce_ingress.id
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "relay_health_from_workforce_ingress" {
  security_group_id            = aws_security_group.relay.id
  referenced_security_group_id = aws_security_group.workforce_ingress.id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "workforce_ingress_to_relay_health" {
  security_group_id            = aws_security_group.workforce_ingress.id
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "model_gateway_from_worker" {
  security_group_id            = aws_security_group.model_gateway.id
  referenced_security_group_id = aws_security_group.worker.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "worker_to_model_gateway" {
  security_group_id            = aws_security_group.worker.id
  referenced_security_group_id = aws_security_group.model_gateway.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "model_gateway_from_agent_executor" {
  security_group_id            = aws_security_group.model_gateway.id
  referenced_security_group_id = aws_security_group.agent_executor.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "Private model inference from one-shot ACP sandboxes"
}

resource "aws_vpc_security_group_egress_rule" "agent_executor_to_model_gateway" {
  security_group_id            = aws_security_group.agent_executor.id
  referenced_security_group_id = aws_security_group.model_gateway.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
  description                  = "No direct model-provider route"
}

resource "aws_vpc_security_group_ingress_rule" "agent_broker_from_executor" {
  security_group_id            = aws_security_group.agent_broker.id
  referenced_security_group_id = aws_security_group.agent_executor.id
  from_port                    = 8444
  to_port                      = 8444
  ip_protocol                  = "tcp"
  description                  = "Purpose-bound job context, action, and result API only"
}

resource "aws_vpc_security_group_egress_rule" "agent_executor_to_broker" {
  security_group_id            = aws_security_group.agent_executor.id
  referenced_security_group_id = aws_security_group.agent_broker.id
  from_port                    = 8444
  to_port                      = 8444
  ip_protocol                  = "tcp"
  description                  = "No direct relay, Analyst, artifact-store, or connector route"
}

resource "aws_vpc_security_group_ingress_rule" "inference_from_model_gateway" {
  security_group_id            = aws_security_group.inference.id
  referenced_security_group_id = aws_security_group.model_gateway.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "model_gateway_to_inference" {
  security_group_id            = aws_security_group.model_gateway.id
  referenced_security_group_id = aws_security_group.inference.id
  from_port                    = 8443
  to_port                      = 8443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "database_from_relay" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "relay_to_database" {
  security_group_id            = aws_security_group.relay.id
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "valkey_from_relay" {
  security_group_id            = aws_security_group.valkey.id
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "relay_to_valkey" {
  security_group_id            = aws_security_group.relay.id
  referenced_security_group_id = aws_security_group.valkey.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "valkey_from_model_gateway" {
  security_group_id            = aws_security_group.valkey.id
  referenced_security_group_id = aws_security_group.model_gateway.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "model_gateway_to_valkey" {
  security_group_id            = aws_security_group.model_gateway.id
  referenced_security_group_id = aws_security_group.valkey.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_services" {
  for_each = {
    relay         = aws_security_group.relay.id
    worker        = aws_security_group.worker.id
    scheduler     = aws_security_group.scheduler.id
    trigger       = aws_security_group.trigger.id
    reminder      = aws_security_group.reminder.id
    model_gateway = aws_security_group.model_gateway.id
    inference     = aws_security_group.inference.id
  }

  security_group_id            = aws_security_group.endpoints.id
  referenced_security_group_id = each.value
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "agent_endpoints_from_executor" {
  security_group_id            = aws_security_group.agent_endpoints.id
  referenced_security_group_id = aws_security_group.agent_executor.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "ECS-managed image pull and log delivery only"
}

resource "aws_vpc_security_group_egress_rule" "agent_executor_to_agent_endpoints" {
  security_group_id            = aws_security_group.agent_executor.id
  referenced_security_group_id = aws_security_group.agent_endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "ECS-managed image pull and log delivery only"
}

resource "aws_vpc_security_group_egress_rule" "services_to_endpoints" {
  for_each = {
    relay         = aws_security_group.relay.id
    worker        = aws_security_group.worker.id
    scheduler     = aws_security_group.scheduler.id
    trigger       = aws_security_group.trigger.id
    reminder      = aws_security_group.reminder.id
    model_gateway = aws_security_group.model_gateway.id
    inference     = aws_security_group.inference.id
  }

  security_group_id            = each.value
  referenced_security_group_id = aws_security_group.endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "services_to_dns_udp" {
  for_each = {
    relay         = aws_security_group.relay.id
    worker        = aws_security_group.worker.id
    scheduler     = aws_security_group.scheduler.id
    trigger       = aws_security_group.trigger.id
    reminder      = aws_security_group.reminder.id
    model_gateway = aws_security_group.model_gateway.id
    inference     = aws_security_group.inference.id
  }

  security_group_id = each.value
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_egress_rule" "services_to_dns_tcp" {
  for_each = {
    relay         = aws_security_group.relay.id
    worker        = aws_security_group.worker.id
    scheduler     = aws_security_group.scheduler.id
    trigger       = aws_security_group.trigger.id
    reminder      = aws_security_group.reminder.id
    model_gateway = aws_security_group.model_gateway.id
    inference     = aws_security_group.inference.id
  }

  security_group_id = each.value
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "agent_executor_to_dns_udp" {
  security_group_id = aws_security_group.agent_executor.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
  description       = "VPC resolver only"
}

resource "aws_vpc_security_group_egress_rule" "agent_executor_to_dns_tcp" {
  security_group_id = aws_security_group.agent_executor.id
  cidr_ipv4         = var.vpc_cidr
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
  description       = "VPC resolver only"
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = aws_vpc.command_center.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids = slice(
    [for key in sort(keys(aws_subnet.private)) : aws_subnet.private[key].id],
    0,
    var.environment == "production" ? 3 : 1,
  )
  security_group_ids = contains(["ecr.api", "ecr.dkr", "logs"], each.value) ? [
    aws_security_group.endpoints.id,
    aws_security_group.agent_endpoints.id,
  ] : [aws_security_group.endpoints.id]

  tags = { Name = "${local.workload_name}-${replace(each.value, ".", "-")}" }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.command_center.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = concat(
    [for route_table in aws_route_table.private : route_table.id],
    [for route_table in aws_route_table.data : route_table.id],
  )

  tags = { Name = "${local.workload_name}-s3" }
}
