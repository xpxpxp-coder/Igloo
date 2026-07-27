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

    def test_edge_is_dormant_by_default_and_fails_closed_when_enabled(self) -> None:
        variables = (ROOT / "variables.tf").read_text(encoding="utf-8")
        edge = (ROOT / "edge.tf").read_text(encoding="utf-8")
        network = (ROOT / "network.tf").read_text(encoding="utf-8")
        self.assertIn('variable "edge_enabled"', variables)
        self.assertIn("default     = false", variables)
        for fragment in (
            'mode            = "verify"',
            "cloudflare_origin_pull_ca_sha256",
            "drop_invalid_header_fields = true",
            "enable_deletion_protection = true",
            'ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"',
            'name     = "exact-snowman-host"',
            'header_name       = "cf-connecting-ip"',
            'name        = "AWSManagedRulesCommonRuleSet"',
            'name        = "AWSManagedRulesKnownBadInputsRuleSet"',
            "sampled_requests_enabled   = false",
            'name = "authorization"',
            'name = "cookie"',
            "query_string {}",
        ):
            self.assertIn(fragment, edge)
        self.assertIn('description                  = "ALB readiness probes only"', network)
        self.assertIn("aws-waf-logs-snowman-command-center-*", (ROOT / "data_plane.tf").read_text(encoding="utf-8"))

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
            'readonlyRootFilesystem = true',
            'user                   = "10001"',
            'drop = ["ALL"]',
            'image                  = var.container_image',
            'BUZZ_AUTO_MIGRATE", value = "false"',
            'SNOWMAN_VALKEY_IAM_ENABLED", value = "true"',
            'SNOWMAN_WORKFORCE_API_ENABLED", value = tostring(var.workforce_api_enabled)',
            'SNOWMAN_WORKFORCE_WORKER_API_ENABLED", value = tostring(var.workforce_worker_api_enabled)',
            'condition     = var.relay_desired_count == 0',
        ):
            self.assertIn(fragment, source)
        self.assertRegex(source, r'actions\s*=\s*\["elasticache:Connect"\]')
        for fragment in (
            'resource "aws_ecs_service" "relay"',
            'desired_count   = var.relay_desired_count',
            'deployment_circuit_breaker',
            'condition     = var.relay_desired_count == 0',
            'assign_public_ip = false',
        ):
            self.assertIn(fragment, source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('"s3:*"', source)
        self.assertNotIn('"kms:*"', source)

    def test_bootstrap_is_one_shot_and_secret_values_never_enter_terraform(self) -> None:
        source = (ROOT / "compute.tf").read_text(encoding="utf-8")
        for fragment in (
            'resource "aws_ecs_task_definition" "bootstrap"',
            'entryPoint             = ["/usr/local/bin/snowman-bootstrap"]',
            'aws_db_instance.postgres.master_user_secret[0].secret_arn',
            '"secretsmanager:PutSecretValue"',
            'sid    = "ReconcileExactWorkforceIdentitySecrets"',
            'resources = local.workforce_identity_secret_arns',
            'SNOWMAN_WORKFORCE_BOOTSTRAP_MANIFEST", value = local.workforce_bootstrap_manifest',
            'SNOWMAN_AGENT_COORDINATOR_RUNTIME_SECRET_ARN", value =',
            'SNOWMAN_AGENT_COORDINATOR_DB_ROLE", value = "snowman_agent_coordinator"',
            'SNOWMAN_PARTITION_MAINTENANCE_MODE", value = "external"',
            'RELAY_OWNER_PUBKEY", valueFrom =',
        ):
            self.assertIn(fragment, source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('SNOWMAN_RELAY_OWNER_PUBKEY", value =', source)

    def test_workforce_bootstrap_manifest_is_role_derived_and_secret_free(self) -> None:
        source = (ROOT / "workforce.tf").read_text(encoding="utf-8")
        variables = (ROOT / "variables.tf").read_text(encoding="utf-8")
        for fragment in (
            'schema_version = "snowman.workforce.bootstrap.v1"',
            "workforce_role_capabilities",
            'deadline_operations   = ["deadline.remind", "workforce.tasks.execute"]',
            "workforce_identity_secret_arns",
            "evaluation_evidence_sha256",
            'secret_kind     = "worker"',
            'secret_kind     = "reminder"',
            "Every team model override must name an evaluated route",
        ):
            self.assertIn(fragment, source)
        self.assertIn('variable "workforce_model_routes"', variables)
        self.assertIn('variable "workforce_community_host"', variables)
        self.assertNotIn("private_key =", source.lower())

    def test_workforce_is_per_identity_private_and_hard_dormant(self) -> None:
        source = (ROOT / "workforce.tf").read_text(encoding="utf-8")
        for fragment in (
            'for_each = var.workforce_profiles',
            'actions   = ["kms:Sign"]',
            'resources = [each.value.analyst_signing_key_arn]',
            'readonlyRootFilesystem = true',
            'capabilities       = { drop = ["ALL"] }',
            'assign_public_ip = false',
            'SNOWMAN_WORKFORCE_NOSTR_PRIVATE_KEY", valueFrom =',
            'SNOWMAN_WORKFORCE_TEAM_IDENTITIES_JSON", valueFrom =',
            'condition     = each.value.desired_count == 0',
            'prefix_list_id    = var.analyst360_private_prefix_list_id',
            'for_each = var.scheduler_profiles',
            'entryPoint             = ["/usr/local/bin/snowman-workforce-scheduler"]',
            'SNOWMAN_WORKFORCE_SCHEDULER_NOSTR_PRIVATE_KEY", valueFrom =',
            'security_groups  = [aws_security_group.scheduler.id]',
            'for_each = var.trigger_profiles',
            'entryPoint             = ["/usr/local/bin/snowman-workforce-trigger"]',
            'SNOWMAN_WORKFORCE_TRIGGER_NOSTR_PRIVATE_KEY", valueFrom =',
            'security_groups  = [aws_security_group.trigger.id]',
            'for_each = var.reminder_profiles',
            'entryPoint             = ["/usr/local/bin/snowman-workforce-reminder"]',
            'SNOWMAN_WORKFORCE_REMINDER_NOSTR_PRIVATE_KEY", valueFrom =',
            'security_groups  = [aws_security_group.reminder.id]',
            'resource "aws_lb" "workforce_private"',
            'internal                   = true',
            'resource "aws_route53_zone" "workforce_private"',
        ):
            self.assertIn(fragment, source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('"kms:*"', source)
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', source)

    def test_agent_executor_is_one_shot_credentialless_and_private(self) -> None:
        source = (ROOT / "agent_executor.tf").read_text(encoding="utf-8")
        variables = (ROOT / "variables.tf").read_text(encoding="utf-8")
        network = (ROOT / "network.tf").read_text(encoding="utf-8")
        outputs = (ROOT / "outputs.tf").read_text(encoding="utf-8")
        for fragment in (
            'for_each = var.agent_runtime_profiles',
            'image                  = each.value.image',
            'entryPoint             = ["/usr/local/bin/snowman-agent-executor"]',
            'readonlyRootFilesystem = true',
            'privileged             = false',
            'capabilities       = { drop = ["ALL"] }',
            'sourceVolume = "workspace", containerPath = "/workspace"',
            'sourceVolume = "tmp", containerPath = "/tmp"',
            'SNOWMAN_AGENT_REQUIRE_BROKERED_JOB_TOKEN',
            'SNOWMAN_AGENT_DISABLE_SELF_UPDATE',
            'snowman-agent-runtime-',
            'sbom_sha256',
            'provenance_sha256',
            'evaluation_evidence_sha256',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source + variables)
        self.assertNotRegex(source, r"(?m)^\s*task_role_arn\s*=")
        self.assertNotIn('resource "aws_ecs_service"', source)
        self.assertNotIn('resource "aws_secretsmanager_secret"', source)
        self.assertNotIn('BUZZ_PRIVATE_KEY', source)
        self.assertNotIn('SNOWMAN_ANALYST', source)
        self.assertIn('resource "aws_security_group" "agent_executor"', network)
        self.assertIn('resource "aws_security_group" "agent_broker"', network)
        self.assertIn('resource "aws_security_group" "agent_broker_ingress"', network)
        self.assertIn('resource "aws_security_group" "agent_endpoints"', network)
        self.assertIn('description                  = "No direct relay, Analyst, artifact-store, or connector route"', network)
        self.assertIn('["ecr.api", "ecr.dkr", "logs"]', network)
        self.assertIn('agent_runtime_task_definitions', outputs)
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', source)

    def test_runtime_image_contains_every_workforce_entrypoint(self) -> None:
        source = (ROOT.parent.parent / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("-p snowman-workforce-worker --bins", source)
        for binary in (
            "snowman-agent-broker",
            "snowman-workforce-worker",
            "snowman-workforce-scheduler",
            "snowman-workforce-trigger",
            "snowman-workforce-reminder",
        ):
            self.assertIn(f"/usr/local/bin/{binary}", source)

    def test_agent_broker_is_private_task_role_free_and_hard_dormant(self) -> None:
        source = (ROOT / "agent_broker.tf").read_text(encoding="utf-8")
        network = (ROOT / "network.tf").read_text(encoding="utf-8")
        preflight = (ROOT / "preflight.tf").read_text(encoding="utf-8")
        for fragment in (
            'resource "aws_lb" "agent_broker_private"',
            'internal                         = true',
            'protocol          = "TLS"',
            'ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"',
            'matcher             = "200-299"',
            'entryPoint             = ["/usr/local/bin/snowman-agent-broker"]',
            'readonlyRootFilesystem = true',
            'privileged             = false',
            'capabilities       = { drop = ["ALL"] }',
            'SNOWMAN_AGENT_BROKER_DATABASE_URL',
            ':DATABASE_URL::',
            'SNOWMAN_AGENT_BROKER_NETWORK_POLICY", value = "private-snowman-only"',
            'enable_execute_command = false',
            'assign_public_ip = false',
            'condition     = var.agent_broker_desired_count == 0',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotRegex(source, r"(?m)^\s*task_role_arn\s*=")
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', source)
        self.assertIn('resource "aws_vpc_security_group_ingress_rule" "database_from_agent_broker"', network)
        self.assertIn('description                  = "No relay, Analyst, model, object, connector, or public route"', network)
        self.assertIn('var.agent_broker_desired_count == 0', preflight)

    def test_public_edge_blocks_private_internal_api_paths(self) -> None:
        source = (ROOT / "edge.tf").read_text(encoding="utf-8")
        for fragment in (
            'name     = "deny-private-internal-api"',
            'search_string         = "/internal/"',
            'positional_constraint = "STARTS_WITH"',
        ):
            self.assertIn(fragment, source)

    def test_agent_coordinator_is_exact_private_and_hard_dormant(self) -> None:
        source = (ROOT / "agent_coordinator.tf").read_text(encoding="utf-8")
        network = (ROOT / "network.tf").read_text(encoding="utf-8")
        preflight = (ROOT / "preflight.tf").read_text(encoding="utf-8")
        for fragment in (
            'resource "aws_kms_key" "agent_job_token"',
            'key_usage                          = "GENERATE_VERIFY_MAC"',
            'customer_master_key_spec           = "HMAC_256"',
            'actions   = ["kms:GenerateMac"]',
            'actions   = ["ecs:RunTask"]',
            'actions = ["ecs:DescribeTasks", "ecs:StopTask"]',
            'actions   = ["iam:PassRole"]',
            'variable = "iam:PassedToService"',
            'entryPoint             = ["/usr/local/bin/snowman-agent-coordinator"]',
            'readonlyRootFilesystem = true',
            'capabilities       = { drop = ["ALL"] }',
            'SNOWMAN_AGENT_COORDINATOR_DATABASE_URL',
            ':DATABASE_URL::',
            'SNOWMAN_AGENT_COORDINATOR_NETWORK_POLICY", value = "private-snowman-only"',
            'enable_execute_command = false',
            'assign_public_ip = false',
            'condition     = var.agent_coordinator_desired_count == 0',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', source)
        self.assertIn('resource "aws_vpc_security_group_ingress_rule" "database_from_agent_coordinator"', network)
        self.assertIn('resource "aws_vpc_security_group_ingress_rule" "agent_coordinator_from_worker"', network)
        self.assertIn('"ecs"', network)
        self.assertIn('var.agent_coordinator_desired_count == 0', preflight)

    def test_model_gateway_is_kms_bound_private_and_hard_dormant(self) -> None:
        source = (ROOT / "model_gateway.tf").read_text(encoding="utf-8")
        data_plane = (ROOT / "data_plane.tf").read_text(encoding="utf-8")
        network = (ROOT / "network.tf").read_text(encoding="utf-8")
        for fragment in (
            'entryPoint             = ["/usr/local/bin/snowman-model-gateway"]',
            'actions   = ["kms:Verify"]',
            'readonlyRootFilesystem = true',
            'capabilities       = { drop = ["ALL"] }',
            'assign_public_ip = false',
            'SNOWMAN_MODEL_GATEWAY_PRINCIPALS_JSON',
            'SNOWMAN_MODEL_GATEWAY_ROUTES_JSON',
            'condition     = var.model_gateway_desired_count == 0',
            'actions = ["sagemaker:InvokeEndpoint"]',
            'endpoint/${route.sagemaker_endpoint_name}',
            'inference-component/${route.sagemaker_inference_component_name}',
        ):
            self.assertIn(fragment, source)
        self.assertRegex(source, r'actions\s*=\s*\["elasticache:Connect"\]')
        self.assertIn('~snowman:model-gateway:nonce:* +set +ping', data_plane)
        self.assertIn('resource "aws_vpc_security_group_egress_rule" "model_gateway_to_inference"', network)
        self.assertIn('resource "aws_vpc_security_group_egress_rule" "model_gateway_to_valkey"', network)
        self.assertIn('"sagemaker.runtime"', network)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('"kms:*"', source)
        self.assertNotIn('"sagemaker:*"', source)
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', source)

    def test_model_gateway_private_link_has_no_public_or_ambient_ingress(self) -> None:
        source = (ROOT / "model_gateway.tf").read_text(encoding="utf-8")
        outputs = (ROOT / "outputs.tf").read_text(encoding="utf-8")
        for fragment in (
            'resource "aws_vpc_endpoint_service" "model_gateway"',
            'acceptance_required        = true',
            'allowed_principals         = sort(tolist(var.model_gateway_consumer_principal_arns))',
            'enforce_security_group_inbound_rules_on_private_link_traffic = "off"',
            'protocol          = "TLS"',
            'ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"',
            'target_type = "ip"',
            'referenced_security_group_id = aws_security_group.model_gateway.id',
        ):
            self.assertIn(fragment, source)
        self.assertRegex(source, r"internal\s*=\s*true")
        self.assertRegex(source, r'load_balancer_type\s*=\s*"network"')
        self.assertIn('output "model_gateway_private_link"', outputs)
        self.assertNotIn('internet_facing', source)
        self.assertNotIn('cidr_ipv4', source)

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

    def test_meeting_services_are_private_dormant_and_media_is_evidence_gated(self) -> None:
        source = (ROOT / "meeting_services.tf").read_text(encoding="utf-8")
        variables = (ROOT / "variables.tf").read_text(encoding="utf-8")
        preflight = (ROOT / "preflight.tf").read_text(encoding="utf-8")
        dockerfile = (ROOT.parent.parent / "Dockerfile").read_text(encoding="utf-8")
        for fragment in (
            'resource "aws_vpc_endpoint_service" "meeting_command"',
            'acceptance_required        = true',
            'allowed_principals         = sort(tolist(var.meeting_command_consumer_principal_arns))',
            'enforce_security_group_inbound_rules_on_private_link_traffic = "off"',
            'entryPoint             = ["/usr/local/bin/snowman-meeting-command-service"]',
            'SNOWMAN_MEETING_COMMAND_DATABASE_ROLE", value = "snowman_meeting_control"',
            'actions   = ["kms:Sign", "kms:GetPublicKey"]',
            'resources = [aws_kms_key.meeting_command_receipts.arn]',
            'condition     = var.meeting_command_desired_count == 0',
            'count = local.meeting_media_runtime_packaged ? 1 : 0',
            'SNOWMAN_MEETING_MEDIA_DATABASE_ROLE", value = "snowman_meeting_media"',
            'SNOWMAN_MEETING_MEDIA_RAW_AUDIO_RETENTION", value = "none"',
            'condition     = var.meeting_media_desired_count == 0',
            'referenced_security_group_id = var.meeting_provider_egress_proxy_security_group_id',
            'max_capacity       = 2',
            'max_capacity       = 4',
            'assign_public_ip = false',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        self.assertIn('default     = false', variables)
        self.assertIn('"api.twilio.com", "api.openai.com", "api.elevenlabs.io"', variables)
        self.assertIn('var.meeting_command_desired_count == 0', preflight)
        self.assertIn('var.meeting_media_desired_count == 0', preflight)
        self.assertIn('!var.meeting_external_provider_egress_enabled', preflight)
        self.assertIn('-p snowman-meeting-command-service --bin snowman-meeting-command-service', dockerfile)
        self.assertIn('/usr/local/bin/snowman-meeting-command-service', dockerfile)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', source)
        self.assertNotIn('ghcr.io/block', source.lower())
        self.assertNotIn('block.xyz', source.lower())
        self.assertNotIn('actions   = ["s3:', source)

    def test_foundation_contains_no_upstream_runtime_authority(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in ROOT.glob("*.tf")
        ).lower()
        for forbidden in (
            "ghcr.io/block",
            "block.xyz",
            "anthropic.com",
        ):
            self.assertNotIn(forbidden, sources)


if __name__ == "__main__":
    unittest.main()
