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
            'SNOWMAN_WORKFORCE_API_ENABLED", value = "false"',
            'condition     = var.relay_desired_count == 0',
        ):
            self.assertIn(fragment, source)
        self.assertRegex(source, r'actions\s*=\s*\["elasticache:Connect"\]')
        self.assertNotIn('resource "aws_ecs_service"', source)
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
            'SNOWMAN_PARTITION_MAINTENANCE_MODE", value = "external"',
            'RELAY_OWNER_PUBKEY", valueFrom =',
        ):
            self.assertIn(fragment, source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('SNOWMAN_RELAY_OWNER_PUBKEY", value =', source)

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
        ):
            self.assertIn(fragment, source)
        self.assertNotIn('resource "aws_secretsmanager_secret_version"', source)
        self.assertNotIn('"kms:*"', source)
        self.assertNotIn('cidr_ipv4 = "0.0.0.0/0"', source)

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
