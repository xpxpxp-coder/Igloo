locals {
  object_buckets = {
    artifacts = {
      retention_mode = "GOVERNANCE"
      retention_days = var.artifact_retention_days
    }
    audit = {
      retention_mode = "COMPLIANCE"
      retention_days = var.audit_retention_days
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "${local.workload_name} managed data and object encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
}

resource "aws_kms_alias" "data" {
  name          = "alias/${local.workload_name}-data"
  target_key_id = aws_kms_key.data.key_id
}

data "aws_iam_policy_document" "logs_kms" {
  statement {
    sid    = "AccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.expected_workload_account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogsEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${var.expected_workload_account_id}:log-group:/snowman/command-center/*"]
    }
  }

  statement {
    sid    = "SnsEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "logs" {
  description             = "${local.workload_name} logs and evidence transport encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
  policy                  = data.aws_iam_policy_document.logs_kms.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${local.workload_name}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

resource "aws_kms_key" "audit_checkpoint" {
  description              = "${local.workload_name} asymmetric audit-checkpoint signatures"
  deletion_window_in_days  = 30
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_3072"
  multi_region             = false
}

resource "aws_kms_alias" "audit_checkpoint" {
  name          = "alias/${local.workload_name}-audit-checkpoint"
  target_key_id = aws_kms_key.audit_checkpoint.key_id
}

resource "aws_s3_bucket" "object" {
  for_each = local.object_buckets

  bucket_prefix       = "snowman-cc-${var.environment}-${each.key}-"
  force_destroy       = false
  object_lock_enabled = true
}

resource "aws_s3_bucket_public_access_block" "object" {
  for_each = aws_s3_bucket.object

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "object" {
  for_each = aws_s3_bucket.object

  bucket = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "object" {
  for_each = aws_s3_bucket.object

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "object" {
  for_each = aws_s3_bucket.object

  bucket = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "object" {
  for_each = aws_s3_bucket.object

  bucket = each.value.id
  rule {
    default_retention {
      mode = local.object_buckets[each.key].retention_mode
      days = local.object_buckets[each.key].retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.object]
}

data "aws_iam_policy_document" "object" {
  for_each = aws_s3_bucket.object

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyWrongEncryptionKey"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${each.value.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.data.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "object" {
  for_each = aws_s3_bucket.object

  bucket = each.value.id
  policy = data.aws_iam_policy_document.object[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.object]
}

resource "aws_s3_bucket_lifecycle_configuration" "object" {
  for_each = aws_s3_bucket.object

  bucket = each.value.id
  rule {
    id     = "retain-noncurrent-evidence"
    status = "Enabled"
    filter {}
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
  }

  depends_on = [aws_s3_bucket_versioning.object]
}

resource "aws_s3_bucket" "media" {
  bucket_prefix = "snowman-cc-${var.environment}-media-"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "media" {
  bucket                  = aws_s3_bucket.media.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "media" {
  bucket = aws_s3_bucket.media.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "media" {
  bucket = aws_s3_bucket.media.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "media" {
  bucket = aws_s3_bucket.media.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.data.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "media" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.media.arn, "${aws_s3_bucket.media.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "media" {
  bucket = aws_s3_bucket.media.id
  policy = data.aws_iam_policy_document.media.json

  depends_on = [aws_s3_bucket_public_access_block.media]
}

resource "aws_s3_bucket_lifecycle_configuration" "media" {
  bucket = aws_s3_bucket.media.id
  rule {
    id     = "expire-superseded-media"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
    noncurrent_version_expiration {
      noncurrent_days = var.media_noncurrent_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.media]
}

resource "aws_db_subnet_group" "postgres" {
  name       = "${local.workload_name}-postgres"
  subnet_ids = [for subnet in aws_subnet.data : subnet.id]
}

resource "aws_db_parameter_group" "postgres" {
  name   = "${local.workload_name}-postgres17"
  family = "postgres17"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  parameter {
    name  = "log_lock_waits"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

resource "aws_db_instance" "postgres" {
  identifier = local.workload_name

  engine         = "postgres"
  engine_version = var.database_engine_version
  instance_class = var.database_instance_class
  db_name        = "snowmancc"
  username       = "snowman_admin"
  port           = 5432

  allocated_storage     = var.database_allocated_storage_gib
  max_allocated_storage = var.database_max_storage_gib
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.data.arn

  manage_master_user_password         = true
  master_user_secret_kms_key_id       = aws_kms_key.data.arn
  iam_database_authentication_enabled = true

  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = var.environment == "production"

  parameter_group_name                  = aws_db_parameter_group.postgres.name
  auto_minor_version_upgrade            = false
  allow_major_version_upgrade           = false
  apply_immediately                     = false
  maintenance_window                    = "sun:08:00-sun:09:00"
  backup_window                         = "06:00-07:00"
  backup_retention_period               = var.backup_retention_days
  copy_tags_to_snapshot                 = true
  delete_automated_backups              = false
  deletion_protection                   = var.deletion_protection
  skip_final_snapshot                   = false
  final_snapshot_identifier             = "${local.workload_name}-final"
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.logs.arn
  performance_insights_retention_period = var.environment == "production" ? 731 : 7
}

resource "aws_elasticache_subnet_group" "valkey" {
  name       = "${local.workload_name}-valkey"
  subnet_ids = [for subnet in aws_subnet.data : subnet.id]
}

resource "aws_elasticache_user" "relay" {
  user_id       = "snowman-${var.environment}-relay"
  user_name     = "snowman-${var.environment}-relay"
  access_string = "on ~* +@all"
  engine        = "valkey"

  authentication_mode {
    type = "iam"
  }
}

resource "aws_elasticache_user_group" "relay" {
  engine        = "valkey"
  user_group_id = "snowman-${var.environment}-relay"
  user_ids      = [aws_elasticache_user.relay.user_id]
}

resource "aws_elasticache_replication_group" "valkey" {
  replication_group_id = "snowman-cc-${var.environment}"
  description          = "${local.workload_name} private coordination cache"

  engine                     = "valkey"
  engine_version             = var.valkey_engine_version
  node_type                  = var.valkey_node_type
  port                       = 6379
  num_cache_clusters         = var.environment == "production" ? 2 : 1
  automatic_failover_enabled = var.environment == "production"
  multi_az_enabled           = var.environment == "production"

  subnet_group_name  = aws_elasticache_subnet_group.valkey.name
  security_group_ids = [aws_security_group.valkey.id]
  user_group_ids     = [aws_elasticache_user_group.relay.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.data.arn

  snapshot_retention_limit   = var.backup_retention_days
  snapshot_window            = "04:00-05:00"
  maintenance_window         = "sun:09:00-sun:10:00"
  apply_immediately          = false
  auto_minor_version_upgrade = false
}
