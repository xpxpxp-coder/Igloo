from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InferenceContractTests(unittest.TestCase):
    def test_activation_is_dormant_and_account_bound(self) -> None:
        variables = (ROOT / "variables.tf").read_text(encoding="utf-8")
        main = (ROOT / "main.tf").read_text(encoding="utf-8")
        self.assertGreaterEqual(variables.count("default     = false"), 3)
        for fragment in (
            "data.aws_caller_identity.current.account_id == var.expected_workload_account_id",
            "var.expected_workload_account_id != var.management_account_id",
            "var.expected_workload_account_id != var.analyst360_workload_account_id",
            "var.foundation_enabled && var.activation_approved",
        ):
            self.assertIn(fragment, main)

    def test_models_are_private_pinned_and_non_persistent(self) -> None:
        variables = (ROOT / "variables.tf").read_text(encoding="utf-8")
        main = (ROOT / "main.tf").read_text(encoding="utf-8")
        for fragment in (
            "snowman-inference/",
            "@sha256:[0-9a-f]{64}",
            "strcontains(model.artifact_key, model.artifact_sha256)",
            "enable_network_isolation = true",
            "security_group_ids = [var.inference_security_group_id]",
            'repository_access_mode = "Platform"',
        ):
            self.assertIn(fragment, variables + main)
        self.assertNotIn("data_capture_config", main)
        self.assertNotIn("api.openai.com", main.lower())
        self.assertNotIn("anthropic.com", main.lower())
        self.assertNotIn("ghcr.io/block", main.lower())

    def test_scale_to_zero_and_cold_start_alarm_are_complete(self) -> None:
        main = (ROOT / "main.tf").read_text(encoding="utf-8")
        for fragment in (
            "min_instance_count = 0",
            "runtime_config           = { copy_count = 0 }",
            "sagemaker:inference-component:DesiredCopyCount",
            "SageMakerInferenceComponentInvocationsPerCopy",
            "NoCapacityInvocationFailures",
            "aws_appautoscaling_policy.from_zero",
            'values = ["user:Application$snowman-inference"]',
            'notification_type         = "FORECASTED"',
        ):
            self.assertIn(fragment, main)

    def test_model_artifacts_are_kms_encrypted_and_locked(self) -> None:
        main = (ROOT / "main.tf").read_text(encoding="utf-8")
        for fragment in (
            "object_lock_enabled = true",
            'mode = "COMPLIANCE"',
            'sse_algorithm     = "aws:kms"',
            'sid     = "DenyWrongModelKmsKey"',
            'actions   = ["s3:GetObject", "s3:GetObjectVersion"]',
            'actions   = ["kms:Decrypt", "kms:DescribeKey"]',
        ):
            self.assertIn(fragment, main)


if __name__ == "__main__":
    unittest.main()
