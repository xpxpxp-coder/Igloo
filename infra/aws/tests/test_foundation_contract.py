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
            'customer_master_key_spec = "RSA_3072"',
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotIn("auth_token", source)
        self.assertNotIn("passwords", source)

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
