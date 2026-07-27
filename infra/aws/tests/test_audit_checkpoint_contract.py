from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AuditCheckpointContractTests(unittest.TestCase):
    def test_runtime_is_dormant_minimized_and_least_privilege(self) -> None:
        source = (ROOT / "audit_checkpoint.tf").read_text(encoding="utf-8")
        data_plane = (ROOT / "data_plane.tf").read_text(encoding="utf-8")
        network = (ROOT / "network.tf").read_text(encoding="utf-8")
        for fragment in (
            'default     = false',
            'state               = var.audit_checkpoint_schedule_enabled ? "ENABLED" : "DISABLED"',
            'entryPoint             = ["/usr/local/bin/snowman-audit-checkpoint"]',
            'command                = ["publish"]',
            'readonlyRootFilesystem = true',
            'capabilities       = { drop = ["ALL"] }',
            '"s3:ListBucketVersions"',
            '"s3:GetObjectVersion"',
            '"s3:PutObject"',
            '"kms:Sign", "kms:Verify", "kms:GetPublicKey"',
            'SNOWMAN_DATABASE_SCHEMA_SHA256',
            'audit_checkpoint_failure',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source + (ROOT / "variables.tf").read_text(encoding="utf-8"))
        for forbidden in (
            '"s3:DeleteObject"',
            '"s3:BypassGovernanceRetention"',
            '"s3:PutObjectRetention"',
            '"kms:ScheduleKeyDeletion"',
            'cidr_ipv4 = "0.0.0.0/0"',
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('retention_mode = "COMPLIANCE"', data_plane)
        self.assertIn('object_lock_enabled = true', data_plane)
        self.assertIn('resource "aws_security_group" "audit_checkpoint"', network)
        self.assertIn('No relay, Analyst, model, connector, or public route', network)

    def test_evidence_schema_has_no_raw_content_fields(self) -> None:
        migration = (ROOT.parent.parent / "migrations" / "0054_snowman_audit_checkpoints.sql").read_text(encoding="utf-8")
        for required in (
            "community_id",
            "sequence",
            "chain_root_sha256",
            "previous_checkpoint_sha256",
            "build_sha256",
            "database_schema_sha256",
            "object_version_id",
            "append-only",
        ):
            self.assertIn(required, migration)
        for forbidden in ("email_address", "transcript_body", "prompt_body", "message_body", "phone_number", "client_row"):
            self.assertNotIn(forbidden, migration)


if __name__ == "__main__":
    unittest.main()
