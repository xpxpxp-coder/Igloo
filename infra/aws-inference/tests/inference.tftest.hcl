mock_provider "aws" {
  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "111111111111" }
  }
  override_data {
    target = data.aws_partition.current
    values = { partition = "aws" }
  }
  override_data {
    target = data.aws_iam_policy_document.sagemaker_assume
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.model_bucket[0]
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.model["delivery"]
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

mock_provider "awscc" {}

variables {
  aws_region                     = "us-west-2"
  environment                    = "staging"
  expected_workload_account_id   = "111111111111"
  management_account_id          = "222222222222"
  analyst360_workload_account_id = "333333333333"
}

run "hard_dormant_by_default" {
  command = plan

  assert {
    condition     = length(aws_s3_bucket.models) == 0 && length(aws_sagemaker_endpoint.model) == 0
    error_message = "The private inference fleet must be empty by default."
  }
}

run "approved_private_scale_zero_fleet" {
  command = plan

  variables {
    foundation_enabled          = true
    endpoints_enabled           = true
    activation_approved         = true
    private_subnet_ids          = ["subnet-000000001", "subnet-000000002"]
    inference_security_group_id = "sg-000000001"
    operations_sns_topic_arn    = "arn:aws:sns:us-west-2:111111111111:snowman-operations"
    models = {
      delivery = {
        endpoint_name                = "snowman-staging-delivery"
        inference_component_name     = "snowman-staging-delivery-component"
        container_image              = "111111111111.dkr.ecr.us-west-2.amazonaws.com/snowman-inference/delivery@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        artifact_key                 = "models/delivery-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.tar.gz"
        artifact_sha256              = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        instance_type                = "ml.g5.xlarge"
        max_instances                = 1
        max_copies                   = 2
        cpu_cores_required           = 2
        accelerator_devices_required = 1
        min_memory_required_mb       = 8192
        max_memory_required_mb       = 16384
      }
    }
  }

  assert {
    condition     = aws_sagemaker_model.model["delivery"].enable_network_isolation
    error_message = "Every model container must be network isolated."
  }
  assert {
    condition     = aws_sagemaker_endpoint_configuration.model["delivery"].production_variants[0].managed_instance_scaling[0].min_instance_count == 0
    error_message = "The endpoint must be allowed to scale to zero idle instances."
  }
  assert {
    condition     = aws_appautoscaling_target.model["delivery"].min_capacity == 0
    error_message = "The inference component must scale to zero copies."
  }
  assert {
    condition     = aws_cloudwatch_metric_alarm.from_zero["delivery"].metric_name == "NoCapacityInvocationFailures"
    error_message = "A zero-capacity invocation must wake the specialist model."
  }
  assert {
    condition     = aws_budgets_budget.inference[0].limit_amount == "250"
    error_message = "The active specialist fleet must remain inside its tag-scoped monthly budget."
  }
}
