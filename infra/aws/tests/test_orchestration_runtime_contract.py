from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class OrchestrationRuntimeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (ROOT / "orchestration_runtime.tf").read_text(encoding="utf-8")

    def test_api_and_every_worker_are_hard_dormant(self) -> None:
        self.assertIn('resource "aws_ecs_service" "orchestration_api"', self.source)
        self.assertIn('resource "aws_ecs_service" "orchestration_worker"', self.source)
        self.assertGreaterEqual(len(re.findall(r"desired_count\s*=\s*0", self.source)), 2)
        self.assertIn("assign_public_ip = false", self.source)
        self.assertIn("enable_execute_command = false", self.source)

    def test_execution_has_no_public_or_provider_route(self) -> None:
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', self.source)
        self.assertNotIn("aws_nat_gateway", self.source)
        self.assertNotIn("api.openai.com", self.source)
        self.assertNotIn("block.xyz", self.source)
        self.assertIn("referenced_security_group_id = aws_security_group.agent_coordinator_ingress.id", self.source)
        self.assertIn("referenced_security_group_id = aws_security_group.workforce_ingress.id", self.source)

    def test_tasks_are_non_root_read_only_and_secret_scoped(self) -> None:
        for fragment in (
            "readonlyRootFilesystem = true",
            "privileged = false",
            'user = "10001"',
            'capabilities = { drop = ["ALL"] }',
            'entryPoint             = ["/usr/local/bin/snowman-orchestration-service"]',
            'entryPoint             = ["/usr/local/bin/snowman-orchestration-worker"]',
            "aws_secretsmanager_secret.orchestration_runtime.arn",
            "aws_secretsmanager_secret.orchestration_worker_identity[each.key].arn",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', self.source)

    def test_contract_has_distinct_scheduler_and_reminder_keys(self) -> None:
        self.assertIn("SNOWMAN_ORCHESTRATION_WORKER_NOSTR_PRIVATE_KEY", self.source)
        self.assertIn("SNOWMAN_ORCHESTRATION_REMINDER_NOSTR_PRIVATE_KEY", self.source)
        coordinator = (ROOT / "agent_coordinator.tf").read_text(encoding="utf-8")
        self.assertIn("SNOWMAN_AGENT_COORDINATOR_ORCHESTRATION_ROUTES_JSON", coordinator)

    def test_outputs_export_only_coordinates(self) -> None:
        output = self.source.split('output "orchestration_runtime_posture"', 1)[1].split("value =", 1)[1]
        for forbidden in ("private_key", "DATABASE_URL", "system_prompt", "client", "message"):
            self.assertNotIn(forbidden, output)


if __name__ == "__main__":
    unittest.main()
