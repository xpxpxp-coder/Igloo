from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent.parent


class ReleaseAssuranceContractTests(unittest.TestCase):
    def test_new_runtime_surfaces_are_bound_to_launch_evidence(self) -> None:
        source = (ROOT / "launch_evidence.tf").read_text(encoding="utf-8")
        for fragment in (
            "var.meeting_command_private_ingress_enabled",
            "var.orchestration_private_ingress_enabled",
            "var.provider_egress_desired_count > 0",
            "var.provider_egress_inspected_network_enabled",
            "var.provider_egress_private_ingress_enabled",
            "meeting_media_report_sha256",
            "orchestration_report_sha256",
            "provider_egress_report_sha256",
            "migration_rehearsal_report_sha256",
            "backup_pitr_report_sha256",
            "license_notice_report_sha256",
        ):
            self.assertIn(fragment, source)

    def test_managed_backup_and_immutable_evidence_posture_fails_closed(self) -> None:
        source = (ROOT / "release_assurance.tf").read_text(encoding="utf-8")
        for fragment in (
            'check "encrypted_backup_and_pitr_posture"',
            "aws_db_instance.postgres.storage_encrypted",
            "aws_db_instance.postgres.delete_automated_backups == false",
            "aws_db_instance.postgres.skip_final_snapshot == false",
            "aws_elasticache_replication_group.valkey.snapshot_retention_limit",
            'aws_s3_bucket.object["audit"].object_lock_enabled',
            'default_retention[0].mode == "COMPLIANCE"',
        ):
            self.assertIn(fragment, source)

    def test_every_new_service_has_an_unexpected_runtime_cost_alarm(self) -> None:
        source = (ROOT / "release_assurance.tf").read_text(encoding="utf-8")
        for fragment in (
            "meeting-command",
            "orchestration-api",
            "hard_dormant_orchestration_worker_started",
            "hard_dormant_meeting_media_started",
            "hard_dormant_provider_egress_started",
            'metric_name         = "RunningTaskCount"',
            'comparison_operator = "GreaterThanThreshold"',
            'threshold           = 0',
            "aws_budgets_budget.monthly.name",
        ):
            self.assertIn(fragment, source)
        service_sources = "\n".join(
            (ROOT / name).read_text(encoding="utf-8")
            for name in (
                "meeting_services.tf",
                "orchestration_runtime.tf",
                "provider_egress_proxy.tf",
            )
        )
        self.assertGreaterEqual(service_sources.count("enable_ecs_managed_tags = true"), 5)
        self.assertGreaterEqual(service_sources.count('propagate_tags          = "SERVICE"'), 5)

    def test_image_pipeline_emits_sbom_and_max_provenance(self) -> None:
        workflow = (REPO_ROOT / ".github" / "workflows" / "docker.yml").read_text(
            encoding="utf-8"
        )
        supply_chain = (ROOT / "supply_chain.tf").read_text(encoding="utf-8")
        self.assertIn("provenance: mode=max", workflow)
        self.assertIn("sbom: true", workflow)
        self.assertIn("DenyReleaseImageDeletion", supply_chain)
        self.assertIn('"ecr:BatchDeleteImage"', supply_chain)
        self.assertGreaterEqual(supply_chain.count("prevent_destroy = true"), 2)


if __name__ == "__main__":
    unittest.main()
