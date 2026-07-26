locals {
  edge_resource_count = var.edge_enabled ? 1 : 0
  edge_log_prefix     = "alb"
  origin_ca_key       = "cloudflare/origin-pull-ca.pem"
}

resource "aws_s3_bucket" "edge_trust" {
  count = local.edge_resource_count

  bucket        = "snowman-cc-${var.environment}-${var.expected_workload_account_id}-edge-trust"
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "edge_trust" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_trust[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "edge_trust" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_trust[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "edge_trust" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_trust[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "origin_pull_ca" {
  count = local.edge_resource_count

  bucket                 = aws_s3_bucket.edge_trust[0].id
  key                    = local.origin_ca_key
  content                = trimspace(var.cloudflare_origin_pull_ca_pem)
  content_type           = "application/x-pem-file"
  server_side_encryption = "AES256"
  source_hash            = sha256(trimspace(var.cloudflare_origin_pull_ca_pem))

  lifecycle {
    precondition {
      condition     = sha256(trimspace(var.cloudflare_origin_pull_ca_pem)) == var.cloudflare_origin_pull_ca_sha256
      error_message = "The Cloudflare origin-pull CA content does not match its reviewed digest."
    }
  }
}

data "aws_iam_policy_document" "edge_trust" {
  count = local.edge_resource_count

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.edge_trust[0].arn, "${aws_s3_bucket.edge_trust[0].arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid    = "ExactElbTrustStoreRead"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["elasticloadbalancing.amazonaws.com"]
    }
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.edge_trust[0].arn}/${local.origin_ca_key}"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.expected_workload_account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "edge_trust" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_trust[0].id
  policy = data.aws_iam_policy_document.edge_trust[0].json
}

resource "aws_s3_bucket" "edge_logs" {
  count = local.edge_resource_count

  bucket        = "snowman-cc-${var.environment}-${var.expected_workload_account_id}-edge-logs"
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "edge_logs" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_logs[0].id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "edge_logs" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_logs[0].id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_versioning" "edge_logs" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_logs[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "edge_logs" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "edge_logs" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_logs[0].id
  rule {
    id     = "governed-retention"
    status = "Enabled"
    filter {}
    expiration { days = var.log_retention_days }
    noncurrent_version_expiration { noncurrent_days = var.log_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

data "aws_iam_policy_document" "edge_logs" {
  count = local.edge_resource_count

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.edge_logs[0].arn, "${aws_s3_bucket.edge_logs[0].arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid    = "ElbLogBucketCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.edge_logs[0].arn]
  }
  statement {
    sid    = "ExactElbLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.edge_logs[0].arn}/${local.edge_log_prefix}/AWSLogs/${var.expected_workload_account_id}/*"]
  }
}

resource "aws_s3_bucket_policy" "edge_logs" {
  count  = local.edge_resource_count
  bucket = aws_s3_bucket.edge_logs[0].id
  policy = data.aws_iam_policy_document.edge_logs[0].json
}

resource "aws_lb_trust_store" "cloudflare" {
  count = local.edge_resource_count

  name                                     = "snowman-${var.environment}-cf-origin"
  ca_certificates_bundle_s3_bucket         = aws_s3_bucket.edge_trust[0].id
  ca_certificates_bundle_s3_key            = aws_s3_object.origin_pull_ca[0].key
  ca_certificates_bundle_s3_object_version = aws_s3_object.origin_pull_ca[0].version_id

  depends_on = [aws_s3_bucket_policy.edge_trust]
}

resource "aws_lb" "edge" {
  count = local.edge_resource_count

  name                       = "snowman-cc-${var.environment}"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.edge.id]
  subnets                    = [for subnet in aws_subnet.public : subnet.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  enable_http2               = true
  idle_timeout               = 300
  preserve_host_header       = true

  access_logs {
    bucket  = aws_s3_bucket.edge_logs[0].id
    prefix  = local.edge_log_prefix
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.edge_logs]
}

resource "aws_lb_target_group" "relay" {
  count = local.edge_resource_count

  name                 = "snowman-cc-${var.environment}"
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

resource "aws_lb_listener" "https" {
  count = local.edge_resource_count

  load_balancer_arn = aws_lb.edge[0].arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.acm_certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  mutual_authentication {
    mode            = "verify"
    trust_store_arn = aws_lb_trust_store.cloudflare[0].arn
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay[0].arn
  }
}

resource "aws_wafv2_web_acl" "edge" {
  count = local.edge_resource_count

  name  = "snowman-command-center-${var.environment}"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "exact-snowman-host"
    priority = 0
    action {
      block {}
    }
    statement {
      not_statement {
        statement {
          byte_match_statement {
            positional_constraint = "EXACTLY"
            search_string         = var.application_hostname
            field_to_match {
              single_header { name = "host" }
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "exact-snowman-host"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "cloudflare-client-rate"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        aggregate_key_type = "FORWARDED_IP"
        limit              = 2000
        forwarded_ip_config {
          fallback_behavior = "MATCH"
          header_name       = "cf-connecting-ip"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "cloudflare-client-rate"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "aws-common-rule-set"
    priority = 10
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common-rule-set"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 11
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-known-bad-inputs"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "snowman-command-center-${var.environment}"
    sampled_requests_enabled   = false
  }
}

resource "aws_wafv2_web_acl_association" "edge" {
  count = local.edge_resource_count

  resource_arn = aws_lb.edge[0].arn
  web_acl_arn  = aws_wafv2_web_acl.edge[0].arn
}

resource "aws_cloudwatch_log_group" "waf" {
  count = local.edge_resource_count

  name              = "aws-waf-logs-snowman-command-center-${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
}

data "aws_iam_policy_document" "waf_logs" {
  count = local.edge_resource_count

  statement {
    sid    = "ExactWafLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.waf[0].arn}:*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.expected_workload_account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${var.expected_workload_account_id}:*"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "waf" {
  count = local.edge_resource_count

  policy_name     = "snowman-command-center-${var.environment}-waf"
  policy_document = data.aws_iam_policy_document.waf_logs[0].json
}

resource "aws_wafv2_web_acl_logging_configuration" "edge" {
  count = local.edge_resource_count

  resource_arn            = aws_wafv2_web_acl.edge[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  redacted_fields {
    single_header { name = "authorization" }
  }
  redacted_fields {
    single_header { name = "cookie" }
  }
  redacted_fields {
    query_string {}
  }

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}
