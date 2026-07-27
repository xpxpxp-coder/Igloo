from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent.parent


class LaunchEvidenceContractTests(unittest.TestCase):
    def test_runtime_activation_requires_exact_fresh_immutable_evidence(self) -> None:
        source = (ROOT / "launch_evidence.tf").read_text(encoding="utf-8")
        for fragment in (
            "runtime_activation_requested",
            "local.activation_mode_authorized",
            "local.launch_evidence_valid",
            'try(var.launch_evidence.container_image, "") == var.container_image',
            "alert_subscription_confirmed",
            "unresolved_critical_findings",
            "unresolved_high_findings",
            'timeadd(plantimestamp(), "-744h")',
            "versionId=",
            "operator_acceptance_sha256",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)

    def test_release_repository_and_signer_are_snowman_owned_and_immutable(self) -> None:
        source = (ROOT / "supply_chain.tf").read_text(encoding="utf-8")
        for fragment in (
            'name                 = "snowman-command-center"',
            'image_tag_mutability = "IMMUTABLE"',
            "scan_on_push = true",
            'encryption_type = "KMS"',
            'key_usage                = "SIGN_VERIFY"',
            'customer_master_key_spec = "ECC_NIST_P256"',
            "force_delete         = false",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotIn("ghcr.io/block", source)
        self.assertNotIn(":latest", source)
        self.assertNotIn(":main", source)

    def test_observability_is_redacted_encrypted_and_snowman_scoped(self) -> None:
        reliability = (ROOT / "reliability.tf").read_text(encoding="utf-8")
        operations = (ROOT / "operations.tf").read_text(encoding="utf-8")
        compute_sources = "\n".join(
            (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "compute.tf",
                "workforce.tf",
                "agent_executor.tf",
                "agent_broker.tf",
                "agent_coordinator.tf",
                "model_gateway.tf",
            )
        )
        for fragment in (
            'namespace     = "Snowman/CommandCenter"',
            "contains no tenant payload",
            "aws_cloudwatch_dashboard",
            "Tenant names, prompts, messages, transcripts",
        ):
            self.assertIn(fragment, reliability)
        self.assertIn("kms_key_id", operations)
        self.assertNotIn("OTEL_EXPORTER_OTLP_ENDPOINT", compute_sources)

    def test_validator_and_recovery_runbook_are_launch_gates(self) -> None:
        validator = (REPO_ROOT / "scripts" / "verify-snowman-launch-evidence.mjs").read_text(
            encoding="utf-8"
        )
        recovery = (
            REPO_ROOT / "docs" / "snowman" / "operations" / "recovery-runbook.md"
        ).read_text(encoding="utf-8")
        for control in (
            "postgres-pitr-restore",
            "valkey-snapshot-restore",
            "s3-version-restore",
            "audit-checkpoint-recovery",
            "dormant-rollback",
            "telemetry-redaction",
            "tenant-isolation",
        ):
            with self.subTest(control=control):
                self.assertIn(f'"{control}"', validator)
        self.assertIn("Never restore over", recovery)
        self.assertIn("simulated database writer", recovery)
        self.assertIn("not yet live", recovery)


if __name__ == "__main__":
    unittest.main()
