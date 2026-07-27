from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AwsPreflightContractTests(unittest.TestCase):
    def test_toolchain_and_provider_are_exactly_pinned(self) -> None:
        source = (ROOT / "versions.tf").read_text(encoding="utf-8")
        self.assertIn('required_version = "= 1.15.8"', source)
        self.assertIn('version = "= 5.100.0"', source)
        self.assertIn("allowed_account_ids = [var.expected_workload_account_id]", source)

    def test_preflight_fails_closed_at_key_boundaries(self) -> None:
        source = (ROOT / "preflight.tf").read_text(encoding="utf-8")
        required = (
            "data.aws_caller_identity.current.account_id == var.expected_workload_account_id",
            "var.expected_workload_account_id != var.management_account_id",
            "var.expected_workload_account_id != var.analyst360_workload_account_id",
            "snowman-command-center@sha256:",
            "var.relay_desired_count == 0",
            "var.worker_desired_count == 0",
            "var.reminder_desired_count == 0",
            "var.model_gateway_desired_count == 0",
            "Runtime desired counts remain hard-zero",
            "!var.external_model_processors_enabled",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)

    def test_image_contract_is_snowman_ecr_digest_only(self) -> None:
        source = (ROOT / "variables.tf").read_text(encoding="utf-8")
        self.assertIn(r"amazonaws\\.com/snowman-command-center@sha256:", source)
        self.assertNotIn(":latest", source)
        self.assertNotIn(":main", source)
        self.assertNotIn("ghcr.io/block", source)

    def test_agent_runtime_contract_is_digest_and_evidence_pinned(self) -> None:
        source = (ROOT / "variables.tf").read_text(encoding="utf-8")
        for fragment in (
            'variable "agent_runtime_profiles"',
            'snowman-agent-runtime-',
            '@sha256:',
            'sbom_sha256',
            'provenance_sha256',
            'evaluation_evidence_sha256',
            'contains(["ARM64", "X86_64"], profile.cpu_architecture)',
        ):
            self.assertIn(fragment, source)


if __name__ == "__main__":
    unittest.main()
