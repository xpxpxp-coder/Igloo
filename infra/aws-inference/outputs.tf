output "model_artifact_bucket" {
  description = "Snowman-only immutable model artifact bucket."
  value       = var.foundation_enabled ? aws_s3_bucket.models[0].bucket : null
}

output "model_gateway_routes" {
  description = "Non-secret exact coordinates to merge into the Command Center model gateway catalog after evaluation approval."
  value = {
    for family, model in local.active_models : family => {
      backend_kind                       = "sagemaker"
      backend_origin                     = null
      sagemaker_endpoint_name            = aws_sagemaker_endpoint.model[family].name
      sagemaker_inference_component_name = model.inference_component_name
    }
  }
}

output "activation_state" {
  value = {
    foundation_enabled  = var.foundation_enabled
    endpoints_enabled   = var.endpoints_enabled
    activation_approved = var.activation_approved
    model_count         = length(var.models)
  }
}
