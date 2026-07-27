locals {
  agent_runtime_repository_arns = {
    for name, profile in var.agent_runtime_profiles : name =>
    "arn:${data.aws_partition.current.partition}:ecr:${var.aws_region}:${var.expected_workload_account_id}:repository/${split("/", split("@", profile.image)[0])[1]}"
  }
}

resource "aws_iam_role" "agent_executor_execution" {
  for_each = var.agent_runtime_profiles

  name               = "${local.workload_name}-agent-${each.key}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_trust.json
}

data "aws_iam_policy_document" "agent_executor_execution" {
  for_each = var.agent_runtime_profiles

  statement {
    sid       = "EcrAuthorization"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid    = "ExactRuntimeImage"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [local.agent_runtime_repository_arns[each.key]]
  }

  statement {
    sid       = "AgentExecutorLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runtime["agent-executor"].arn}:*"]
  }
}

resource "aws_iam_role_policy" "agent_executor_execution" {
  for_each = var.agent_runtime_profiles

  name   = "exact-image-and-redacted-logs"
  role   = aws_iam_role.agent_executor_execution[each.key].id
  policy = data.aws_iam_policy_document.agent_executor_execution[each.key].json
}

resource "aws_ecs_task_definition" "agent_executor" {
  for_each = var.agent_runtime_profiles

  family                   = "${local.workload_name}-agent-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(each.value.cpu)
  memory                   = tostring(each.value.memory)
  execution_role_arn       = aws_iam_role.agent_executor_execution[each.key].arn

  tags = {
    RuntimeId              = each.value.runtime_id
    ImageDigest            = split("@sha256:", each.value.image)[1]
    SbomDigest             = each.value.sbom_sha256
    ProvenanceDigest       = each.value.provenance_sha256
    EvaluationEvidence     = each.value.evaluation_evidence_sha256
    ExecutionMode          = "one-shot"
    AmbientTaskCredentials = "none"
  }

  # Deliberately omit task_role_arn. The untrusted ACP/runtime process must not
  # receive ECS task credentials, even when an empty IAM policy seems harmless.

  runtime_platform {
    cpu_architecture        = each.value.cpu_architecture
    operating_system_family = "LINUX"
  }

  ephemeral_storage {
    size_in_gib = each.value.ephemeral_storage_gib
  }

  volume {
    name = "workspace"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "agent-${each.key}"
    image                  = each.value.image
    essential              = true
    readonlyRootFilesystem = true
    privileged             = false
    user                   = "10001"
    entryPoint             = ["/usr/local/bin/snowman-agent-executor"]
    stopTimeout            = 120
    linuxParameters = {
      initProcessEnabled = true
      capabilities       = { drop = ["ALL"] }
    }
    environment = [
      { name = "SNOWMAN_AGENT_RUNTIME_ID", value = each.value.runtime_id },
      { name = "SNOWMAN_AGENT_BROKER_URL", value = var.agent_broker_url },
      { name = "SNOWMAN_MODEL_GATEWAY_URL", value = var.agent_model_gateway_url },
      { name = "SNOWMAN_AGENT_MAX_TASK_SECONDS", value = tostring(each.value.max_task_seconds) },
      { name = "SNOWMAN_AGENT_NETWORK_POLICY", value = "private-snowman-only" },
      { name = "SNOWMAN_AGENT_REQUIRE_BROKERED_JOB_TOKEN", value = "true" },
      { name = "SNOWMAN_AGENT_DISABLE_SELF_UPDATE", value = "true" },
    ]
    mountPoints = [
      { sourceVolume = "workspace", containerPath = "/workspace", readOnly = false },
      { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
    ]
    volumesFrom = []
    ulimits = [
      { name = "nofile", softLimit = 4096, hardLimit = 4096 },
      { name = "nproc", softLimit = 512, hardLimit = 512 },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.runtime["agent-executor"].name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = each.key
        mode                  = "non-blocking"
        max-buffer-size       = "1m"
      }
    }
  }])

  lifecycle {
    precondition {
      condition = startswith(
        each.value.image,
        "${var.expected_workload_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/snowman-agent-runtime-"
      )
      error_message = "Every agent runtime image must come from the exact Snowman workload account and region."
    }
    precondition {
      condition     = var.agent_broker_url != "" && var.agent_model_gateway_url != ""
      error_message = "Agent runtime profiles require exact private Snowman broker and model-gateway URLs."
    }
  }
}
