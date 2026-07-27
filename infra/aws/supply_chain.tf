resource "aws_kms_key" "release_signing" {
  description              = "${local.workload_name} asymmetric release and image signatures"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  multi_region             = false
}

resource "aws_kms_alias" "release_signing" {
  name          = "alias/${local.workload_name}-release-signing"
  target_key_id = aws_kms_key.release_signing.key_id
}

resource "aws_ecr_repository" "command_center" {
  name                 = "snowman-command-center"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.data.arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

data "aws_iam_policy_document" "command_center_repository" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["ecr:*"]
    resources = [aws_ecr_repository.command_center.arn]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_ecr_repository_policy" "command_center" {
  repository = aws_ecr_repository.command_center.name
  policy     = data.aws_iam_policy_document.command_center_repository.json
}
