from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AwsFoundationContractTests(unittest.TestCase):
    def test_network_has_no_nat_or_private_internet_egress(self) -> None:
        source = (ROOT / "network.tf").read_text(encoding="utf-8")
        self.assertNotIn('resource "aws_nat_gateway"', source)
        self.assertNotIn('resource "aws_eip"', source)
        self.assertEqual(source.count('destination_cidr_block = "0.0.0.0/0"'), 1)
        self.assertIn('for_each = var.cloudflare_origin_ipv4_cidrs', source)
        self.assertIn('referenced_security_group_id = aws_security_group.endpoints.id', source)
        for service in (
            '"ecr.api"',
            '"ecr.dkr"',
            '"logs"',
            '"kms"',
            '"secretsmanager"',
            '"sts"',
        ):
            self.assertIn(service, source)

    def test_managed_state_is_encrypted_locked_and_private(self) -> None:
        source = (ROOT / "data_plane.tf").read_text(encoding="utf-8")
        required = (
            'object_lock_enabled = true',
            'retention_mode = "COMPLIANCE"',
            'storage_encrypted',
            'manage_master_user_password',
            'iam_database_authentication_enabled = true',
            'publicly_accessible    = false',
            'deletion_protection',
            'transit_encryption_enabled = true',
            'at_rest_encryption_enabled = true',
            'authentication_mode',
            'type = "iam"',
            'engine        = "valkey"',
            '~buzz:* &buzz:*',
            'customer_master_key_spec = "RSA_3072"',
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotIn("auth_token", source)
        self.assertNotIn("passwords", source)
        self.assertNotIn("+@all", source)

    def test_runtime_uses_streaming_iam_credentials(self) -> None:
        connection = (ROOT.parent.parent / "crates" / "buzz-pubsub" / "src" / "connection.rs").read_text(encoding="utf-8")
        auth = (ROOT.parent.parent / "crates" / "snowman-aws-auth" / "src" / "lib.rs").read_text(encoding="utf-8")
        outputs = (ROOT / "outputs.tf").read_text(encoding="utf-8")
        for fragment in (
            "set_credentials_provider",
            "set_automatic_resubscription",
            "set_push_sender",
        ):
            self.assertIn(fragment, connection)
        for fragment in (
            'name("elasticache")',
            "SignatureLocation::QueryParams",
            "TOKEN_REFRESH",
            "StreamingCredentialsProvider",
        ):
            self.assertIn(fragment, auth)
        for fragment in (
            "SNOWMAN_VALKEY_IAM_ENABLED",
            "SNOWMAN_VALKEY_IAM_USER_ID",
            "SNOWMAN_VALKEY_CACHE_NAME",
            "elasticache:Connect",
        ):
            self.assertIn(fragment, outputs)

    def test_dormant_relay_compute_is_least_privilege_and_non_root(self) -> None:
        source = (ROOT / "compute.tf").read_text(encoding="utf-8")
        for fragment in (
            'actions   = ["elasticache:Connect"]',
            'readonlyRootFilesystem = true',
            'user                   = "10001"',
            'drop = ["ALL"]',
            'image                  = var.container_image',
            'BUZZ_AUTO_MIGRATE", value = "false"',
            'SNOWMAN_VALKEY_IAM_ENABLED", value = "true"',
            'SNOWMAN_WORKFORCE_API_ENABLED", value = "false"',
            'condition     = var.relay_desired_count == 0',
        ):
            self.assertIn(fragment, source)
        self.assertNotIn('resource "aws_ecs_service"', source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('"s3:*"', source)
        self.assertNotIn('"kms:*"', source)

    def test_operations_are_encrypted_alerted_and_budgeted(self) -> None:
        source = (ROOT / "operations.tf").read_text(encoding="utf-8")
        for fragment in (
            'value = "enhanced"',
            'kms_key_id',
            'aws_sns_topic_subscription',
            'aws_budgets_budget',
            'notification_type         = "FORECASTED"',
            'notification_type         = "ACTUAL"',
            'treat_missing_data  = "breaching"',
        ):
            self.assertIn(fragment, source)

    def test_foundation_contains_no_upstream_runtime_authority(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in ROOT.glob("*.tf")
        ).lower()
        for forbidden in (
            "ghcr.io/block",
            "block.xyz",
            "api.openai.com",
            "anthropic.com",
        ):
            self.assertNotIn(forbidden, sources)


if __name__ == "__main__":
    unittest.main()
