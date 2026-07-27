data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  workload_name = "snowman-inference-${var.environment}"
  active_models = var.endpoints_enabled ? var.models : {}
  tags = {
    Application   = "snowman-inference"
    Environment   = var.environment
    Owner         = "snowman-ai"
    ManagedBy     = "terraform"
    DataAuthority = "no-client-data-persistence"
    Soc2Scope     = "governed-agent-inference"
  }
  model_repository_names = {
    for family, model in var.models : family => split("@", split(".amazonaws.com/", model.container_image)[1])[0]
  }
}

check "account_and_activation_boundary" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.expected_workload_account_id
    error_message = "The active AWS identity does not match the exact Snowman inference workload account."
  }
  assert {
    condition = (
      var.expected_workload_account_id != var.management_account_id &&
      var.expected_workload_account_id != var.analyst360_workload_account_id
    )
    error_message = "Inference may not run in the management or Analyst 360 workload account."
  }
  assert {
    condition     = !var.endpoints_enabled || (var.foundation_enabled && var.activation_approved && length(var.models) > 0)
    error_message = "Endpoints remain hard-dormant until foundation, explicit activation, and a non-empty governed model fleet are provided."
  }
  assert {
    condition = (
      length(distinct([for model in values(var.models) : model.endpoint_name])) == length(var.models) &&
      length(distinct([for model in values(var.models) : model.inference_component_name])) == length(var.models)
    )
    error_message = "Endpoint and inference-component names must be unique."
  }
}

resource "aws_kms_key" "models" {
  count                   = var.foundation_enabled ? 1 : 0
  description             = "Snowman ${var.environment} immutable model artifacts"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "models" {
  count         = var.foundation_enabled ? 1 : 0
  name          = "alias/${local.workload_name}-models"
  target_key_id = aws_kms_key.models[0].key_id
}

resource "aws_s3_bucket" "models" {
  count               = var.foundation_enabled ? 1 : 0
  bucket              = "snowman-models-${var.environment}-${var.expected_workload_account_id}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "models" {
  count  = var.foundation_enabled ? 1 : 0
  bucket = aws_s3_bucket.models[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "models" {
  count  = var.foundation_enabled ? 1 : 0
  bucket = aws_s3_bucket.models[0].id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.models[0].arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "models" {
  count  = var.foundation_enabled ? 1 : 0
  bucket = aws_s3_bucket.models[0].id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.environment == "production" ? 365 : 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "models" {
  count                   = var.foundation_enabled ? 1 : 0
  bucket                  = aws_s3_bucket.models[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "model_bucket" {
  count = var.foundation_enabled ? 1 : 0
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [aws_s3_bucket.models[0].arn, "${aws_s3_bucket.models[0].arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid     = "DenyNonKmsModelUploads"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.models[0].arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
  statement {
    sid     = "DenyWrongModelKmsKey"
    effect  = "Deny"
    actions = ["s3:PutObject"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.models[0].arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.models[0].arn]
    }
  }
}

resource "aws_s3_bucket_policy" "models" {
  count  = var.foundation_enabled ? 1 : 0
  bucket = aws_s3_bucket.models[0].id
  policy = data.aws_iam_policy_document.model_bucket[0].json
}

data "aws_iam_policy_document" "sagemaker_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["sagemaker.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "model" {
  for_each           = var.foundation_enabled ? var.models : {}
  name               = "${local.workload_name}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.sagemaker_assume.json
}

data "aws_iam_policy_document" "model" {
  for_each = var.foundation_enabled ? var.models : {}
  statement {
    sid       = "ReadExactModelArtifact"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.models[0].arn}/${each.value.artifact_key}"]
  }
  statement {
    sid       = "DecryptModelArtifacts"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.models[0].arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.aws_region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "PullExactSnowmanImage"
    effect    = "Allow"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["arn:${data.aws_partition.current.partition}:ecr:${var.aws_region}:${var.expected_workload_account_id}:repository/${local.model_repository_names[each.key]}"]
  }
  statement {
    sid       = "AuthenticateToEcr"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid    = "ManageOnlyRequiredVpcInterfaces"
    effect = "Allow"
    actions = [
      "ec2:CreateNetworkInterface",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DeleteNetworkInterface",
      "ec2:DeleteNetworkInterfacePermission",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "model" {
  for_each = var.foundation_enabled ? var.models : {}
  name     = "least-privilege-model-runtime"
  role     = aws_iam_role.model[each.key].id
  policy   = data.aws_iam_policy_document.model[each.key].json
}

resource "aws_sagemaker_model" "model" {
  for_each                 = local.active_models
  name                     = "${local.workload_name}-${each.key}"
  execution_role_arn       = aws_iam_role.model[each.key].arn
  enable_network_isolation = true

  primary_container {
    image          = each.value.container_image
    model_data_url = "s3://${aws_s3_bucket.models[0].bucket}/${each.value.artifact_key}"
    image_config {
      repository_access_mode = "Platform"
    }
  }

  vpc_config {
    subnets            = var.private_subnet_ids
    security_group_ids = [var.inference_security_group_id]
  }

  depends_on = [aws_iam_role_policy.model]
}

resource "aws_sagemaker_endpoint_configuration" "model" {
  for_each           = local.active_models
  name               = "${each.value.endpoint_name}-config"
  execution_role_arn = aws_iam_role.model[each.key].arn
  kms_key_arn        = aws_kms_key.models[0].arn

  production_variants {
    variant_name           = "AllTraffic"
    instance_type          = each.value.instance_type
    initial_instance_count = 1
    initial_variant_weight = 1
    enable_ssm_access      = false

    managed_instance_scaling {
      status             = "ENABLED"
      min_instance_count = 0
      max_instance_count = each.value.max_instances
    }
  }
}

resource "aws_sagemaker_endpoint" "model" {
  for_each             = local.active_models
  name                 = each.value.endpoint_name
  endpoint_config_name = aws_sagemaker_endpoint_configuration.model[each.key].name
}

resource "awscc_sagemaker_inference_component" "model" {
  for_each                 = local.active_models
  inference_component_name = each.value.inference_component_name
  endpoint_name            = aws_sagemaker_endpoint.model[each.key].name
  variant_name             = "AllTraffic"
  runtime_config           = { copy_count = 0 }
  specification = {
    model_name = aws_sagemaker_model.model[each.key].name
    compute_resource_requirements = {
      number_of_cpu_cores_required           = each.value.cpu_cores_required
      number_of_accelerator_devices_required = each.value.accelerator_devices_required
      min_memory_required_in_mb              = each.value.min_memory_required_mb
      max_memory_required_in_mb              = each.value.max_memory_required_mb
    }
    startup_parameters = {
      model_data_download_timeout_in_seconds            = each.value.model_download_timeout_seconds
      container_startup_health_check_timeout_in_seconds = each.value.container_startup_timeout_seconds
    }
  }
  tags = [for key, value in local.tags : { key = key, value = value }]
}

resource "aws_appautoscaling_target" "model" {
  for_each           = local.active_models
  service_namespace  = "sagemaker"
  resource_id        = "inference-component/${each.value.inference_component_name}"
  scalable_dimension = "sagemaker:inference-component:DesiredCopyCount"
  min_capacity       = 0
  max_capacity       = each.value.max_copies
  depends_on         = [awscc_sagemaker_inference_component.model]
}

resource "aws_appautoscaling_policy" "target" {
  for_each           = local.active_models
  name               = "${each.value.inference_component_name}-target"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.model[each.key].service_namespace
  resource_id        = aws_appautoscaling_target.model[each.key].resource_id
  scalable_dimension = aws_appautoscaling_target.model[each.key].scalable_dimension

  target_tracking_scaling_policy_configuration {
    target_value       = 1
    scale_in_cooldown  = 600
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "SageMakerInferenceComponentInvocationsPerCopy"
    }
  }
}

resource "aws_appautoscaling_policy" "from_zero" {
  for_each           = local.active_models
  name               = "${each.value.inference_component_name}-from-zero"
  policy_type        = "StepScaling"
  service_namespace  = aws_appautoscaling_target.model[each.key].service_namespace
  resource_id        = aws_appautoscaling_target.model[each.key].resource_id
  scalable_dimension = aws_appautoscaling_target.model[each.key].scalable_dimension

  step_scaling_policy_configuration {
    adjustment_type         = "ChangeInCapacity"
    cooldown                = 60
    metric_aggregation_type = "Maximum"
    step_adjustment {
      metric_interval_lower_bound = 0
      scaling_adjustment          = 1
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "from_zero" {
  for_each            = local.active_models
  alarm_name          = "${each.value.inference_component_name}-no-capacity"
  alarm_description   = "Wake a zero-capacity Snowman inference component and notify operations."
  namespace           = "AWS/SageMaker"
  metric_name         = "NoCapacityInvocationFailures"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  dimensions = {
    InferenceComponentName = each.value.inference_component_name
  }
  alarm_actions = [aws_appautoscaling_policy.from_zero[each.key].arn, var.operations_sns_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "invocation_errors" {
  for_each            = local.active_models
  alarm_name          = "${each.value.inference_component_name}-errors"
  alarm_description   = "Snowman specialist model invocation errors exceed the accepted floor."
  namespace           = "AWS/SageMaker"
  metric_name         = "Invocation5XXErrors"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions = {
    EndpointName = each.value.endpoint_name
    VariantName  = "AllTraffic"
  }
  alarm_actions = [var.operations_sns_topic_arn]
}

resource "aws_budgets_budget" "inference" {
  count        = var.endpoints_enabled ? 1 : 0
  name         = "${local.workload_name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_inference_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Application$snowman-inference"]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 50
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_sns_topic_arns = [var.operations_sns_topic_arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [var.operations_sns_topic_arn]
  }

  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [var.operations_sns_topic_arn]
  }
}
