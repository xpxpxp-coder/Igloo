#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(resolve(repoRoot, path), "utf8");
const identity = JSON.parse(read("product/identity.json"));

const runtimeAuthorityFiles = [
  "crates/buzz-relay/src/config.rs",
  "crates/buzz-relay/src/authorization.rs",
  "crates/buzz-relay/src/api/workforce.rs",
  "crates/buzz-relay/src/api/analyst_integration.rs",
  "crates/buzz-relay/src/nip11.rs",
  "crates/buzz-push-gateway/src/config.rs",
  "crates/buzz-push-gateway/src/http.rs",
  "crates/buzz-pairing-cli/src/main.rs",
  "crates/buzz-dev-mcp/src/paths.rs",
  "crates/buzz-dev-mcp/src/shell.rs",
  "crates/buzz-dev-mcp/src/shim.rs",
  "crates/buzz-dev-mcp/src/view_image.rs",
  "crates/buzz-agent/src/config.rs",
  "crates/buzz-workflow/src/schema.rs",
  "crates/buzz-db/src/workforce.rs",
  "crates/buzz-db/src/workforce_identity.rs",
  "crates/buzz-db/src/analyst_integration.rs",
  "crates/snowman-workforce/src/lib.rs",
  "migrations/0025_snowman_workforce.sql",
  "migrations/0026_snowman_workforce_identity.sql",
  "migrations/0027_snowman_workforce_request_contract.sql",
  "migrations/0028_snowman_workforce_claim_idempotency.sql",
  "migrations/0029_snowman_analyst_event_boundary.sql",
  "desktop/src-tauri/src/commands/agent_models.rs",
  "desktop/src-tauri/src/builderlab.rs",
  "desktop/src-tauri/src/relay.rs",
  "desktop/src-tauri/src/commands/workspace.rs",
  "desktop/src-tauri/src/managed_agents/discovery.rs",
  "desktop/src-tauri/src/managed_agents/personas.rs",
  "desktop/src-tauri/src/managed_agents/teams.rs",
  "desktop/src-tauri/src/managed_agents/nest_agents.md",
  "desktop/src-tauri/src/mesh_llm/transport_policy.rs",
  "desktop/src-tauri/tauri.conf.json",
  "desktop/src-tauri/tauri.dev.conf.json",
  "desktop/src/features/communities/hostedCommunityApi.ts",
  "desktop/src/features/communities/relayProbe.ts",
  "desktop/src/features/onboarding/welcomeCanvas.ts",
  "desktop/src/features/settings/hooks/use-updater.ts",
  "web/src/shared/lib/buzz-download.ts",
  "web/src/shared/lib/relay-url.ts",
  "mobile/lib/features/pairing/pairing_provider.dart",
  "mobile/lib/shared/deeplink/deep_link.dart",
  ".github/workflows/release.yml",
  "deploy/compose/compose.yml",
  "deploy/charts/buzz/values.yaml",
  "deploy/charts/buzz/templates/deployment.yaml",
  "deploy/charts/buzz-push-gateway/values.yaml",
  "deploy/charts/buzz-push-gateway/values-production.yaml",
  "deploy/charts/buzz-push-gateway/values.schema.json",
  "infra/aws/versions.tf",
  "infra/aws/variables.tf",
  "infra/aws/preflight.tf",
];

const forbidden = [
  ["Block GitHub", /github\.com\/block\//i],
  ["Block GitHub API", /api\.github\.com\/repos\/block\//i],
  ["Block GHCR", /ghcr\.io\/block\//i],
  ["Builderlab runtime", /(?:^|[^a-z0-9-])(?:[a-z0-9-]+\.)*builderlab\.xyz\b/i],
  ["Buzz production domain", /(?:^|[^a-z0-9-])(?:[a-z0-9-]+\.)*buzz\.xyz\b/i],
  ["public Nostr relay", /relay\.damus\.io|nos\.lol|nostr\.wine/i],
  ["public mesh relay", /mesh-llm\.iroh\.link|default_relay_map\(\)/i],
  ["mutable main image", /image:\s*[^\n]*(?::main|:latest)\b/i],
  ["remote runtime avatar", /const\s+\w*AVATAR\w*:\s*&str\s*=\s*"https?:\/\//i],
  ["remote installer command", /install_commands(?:_windows)?:\s*&\[[^\]]*https?:\/\//is],
];

const failures = [];
for (const path of runtimeAuthorityFiles) {
  const source = read(path);
  for (const [label, pattern] of forbidden) {
    if (pattern.test(source)) failures.push(`${path}: ${label}`);
  }
}

function requireFragment(path, fragment, reason) {
  if (!read(path).includes(fragment)) failures.push(`${path}: ${reason}`);
}

const releaseSource = read("web/src/shared/lib/buzz-download.ts");
if (/fetch\(\s*["'`]https?:\/\//i.test(releaseSource)) {
  failures.push("web/src/shared/lib/buzz-download.ts: cross-origin release fetch");
}
requireFragment(
  "desktop/src-tauri/src/commands/workspace.rs",
  "validate_snowman_relay_url(&relay_url)?;",
  "workspace relay changes must enforce the Snowman transport boundary",
);
requireFragment(
  "web/src/shared/lib/relay-url.ts",
  "Relay URL is outside the Snowman-controlled boundary.",
  "browser relay connections must enforce the Snowman transport boundary",
);
requireFragment(
  "mobile/lib/features/pairing/pairing_provider.dart",
  "Relay URL is outside the Snowman-controlled boundary",
  "mobile pairing must enforce the Snowman transport boundary",
);
requireFragment(
  "crates/snowman-workforce/src/lib.rs",
  "DisallowedModelOverride",
  "per-agent model overrides must remain governed by the approved catalog",
);
requireFragment(
  "crates/snowman-workforce/src/lib.rs",
  "ExecuteAutomatically",
  "proactive action policy must distinguish automatic work from human-gated work",
);
requireFragment(
  "crates/snowman-workforce/src/lib.rs",
  "producer_identities",
  "client-ready work must use an independently identified quality/risk reviewer",
);
requireFragment(
  "infra/aws/preflight.tf",
  "var.expected_workload_account_id != var.analyst360_workload_account_id",
  "production Command Center and Analyst 360 AWS authority must remain separate",
);
requireFragment(
  "infra/aws/preflight.tf",
  "!var.external_model_processors_enabled",
  "AWS baseline must fail closed on external model processors",
);
requireFragment(
  "infra/aws/preflight.tf",
  "var.relay_desired_count == 0 && var.worker_desired_count == 0",
  "baseline staging must remain dormant",
);
requireFragment(
  "crates/buzz-workflow/src/schema.rs",
  "send_dm is not enabled",
  "unimplemented workflow actions must fail definition validation",
);
requireFragment(
  "crates/buzz-workflow/src/schema.rs",
  "outside the Snowman-controlled boundary",
  "workflow webhooks must enforce the Snowman destination boundary",
);
requireFragment(
  "crates/buzz-workflow/src/schema.rs",
  "literal credential headers are forbidden",
  "workflow webhook credentials must be brokered",
);
requireFragment(
  "crates/buzz-agent/src/config.rs",
  "validate_snowman_model_base_url(&self.base_url)?;",
  "agent inference must enforce the Snowman model boundary",
);
requireFragment(
  "crates/buzz-agent/src/config.rs",
  "https://models.snowmanai.org/openai/v1",
  "agent inference must default through the Snowman model gateway",
);
requireFragment(
  "desktop/src-tauri/src/commands/agent_models.rs",
  "validate_snowman_model_base_url",
  "model discovery must enforce the Snowman model boundary",
);
requireFragment(
  "web/src/shared/lib/buzz-download.ts",
  'export const BUZZ_RELEASES_URL = "/downloads";',
  "release page must remain same-origin",
);
requireFragment(
  "crates/buzz-dev-mcp/src/shell.rs",
  'SNOWMAN_AGENT_SHELL_CAPABILITY").as_deref()',
  "agent shell must be capability-gated and default off",
);
requireFragment(
  "crates/buzz-dev-mcp/src/shell.rs",
  "if !state.shell_capability_granted",
  "agent shell must enforce its startup capability snapshot",
);
requireFragment(
  "crates/buzz-dev-mcp/src/paths.rs",
  "path escapes the Snowman agent workspace",
  "agent file tools must reject workspace escape",
);
requireFragment(
  "crates/buzz-dev-mcp/src/shim.rs",
  'remove_var("BUZZ_PRIVATE_KEY")',
  "agent tool server must remove the ambient relay private key",
);
requireFragment(
  "crates/buzz-dev-mcp/src/view_image.rs",
  'SNOWMAN_AGENT_NETWORK_CAPABILITY").as_deref()',
  "agent network image reads must be capability-gated",
);
requireFragment(
  "web/src/shared/lib/buzz-download.ts",
  '!asset.browser_download_url.startsWith("//")',
  "release assets must reject protocol-relative destinations",
);
requireFragment(
  "crates/buzz-relay/src/config.rs",
  "Err(_) => None,",
  "push delivery must default off",
);
requireFragment(
  "crates/buzz-relay/src/authorization.rs",
  "resolve_workforce_principal",
  "governed relay authorization must resolve a live workforce identity",
);
requireFragment(
  "crates/buzz-db/src/workforce.rs",
  "FOR UPDATE SKIP LOCKED",
  "workforce workers must use durable concurrent claims",
);
requireFragment(
  "crates/buzz-relay/src/api/workforce.rs",
  '"workforce.requests.create"',
  "workforce request intake must require an exact human capability",
);
requireFragment(
  "crates/buzz-relay/src/api/analyst_integration.rs",
  "verify_kms_signature(&assertion)",
  "Analyst event ingress must verify an asymmetric KMS request assertion",
);
requireFragment(
  "crates/buzz-relay/src/api/analyst_integration.rs",
  "tenant.community()",
  "Analyst event ingress must derive its community server-side",
);
requireFragment(
  "crates/buzz-relay/src/api/analyst_integration.rs",
  "sign_receipt(&binding.receipt_kms_key_arn",
  "Analyst event ingress must sign delivery evidence with the bound receipt key",
);
requireFragment(
  "migrations/0029_snowman_analyst_event_boundary.sql",
  "CHECK (request_kms_key_arn <> receipt_kms_key_arn)",
  "Analyst request and Command Center receipt keys must be separate",
);
requireFragment(
  "crates/buzz-relay/src/api/workforce.rs",
  "snowman_workforce_worker_api_enabled",
  "private worker routes must remain independently disabled on public relay tasks",
);
requireFragment(
  "crates/buzz-relay/src/api/workforce.rs",
  '"workforce.tasks.execute"',
  "private worker routes must require an exact service capability",
);
requireFragment(
  "migrations/0028_snowman_workforce_claim_idempotency.sql",
  "idx_snowman_task_leases_worker_claim",
  "worker lease claims must be idempotent across lost responses",
);
requireFragment(
  "crates/buzz-relay/src/api/workforce.rs",
  "tenant.community()",
  "workforce requests must use the server-derived tenant",
);
requireFragment(
  "crates/buzz-relay/src/api/workforce.rs",
  'required_capabilities: vec!["workforce.plan".to_string()]',
  "public intake must enqueue only a bounded planning capability",
);
requireFragment(
  "crates/buzz-relay/src/api/workforce.rs",
  'strip_prefix("analyst360:sha256:")',
  "workforce context must use immutable Analyst 360 evidence coordinates",
);
requireFragment(
  "crates/buzz-db/src/workforce.rs",
  "execution_snapshot_sha256",
  "human approvals must bind to an exact execution snapshot",
);
requireFragment(
  "crates/buzz-db/src/workforce.rs",
  "pg_advisory_xact_lock",
  "workforce event and spend writers must serialize conflicting mutations",
);
requireFragment(
  "crates/buzz-db/src/workforce.rs",
  "snowman.work.event.v1",
  "workforce lifecycle events must use a domain-separated hash chain",
);
requireFragment(
  "crates/buzz-db/src/workforce_identity.rs",
  "s.revoked_at IS NULL AND s.expires_at > NOW()",
  "human workforce keys must require live non-revoked sessions",
);
requireFragment(
  "migrations/0026_snowman_workforce_identity.sql",
  "snowman_workforce_capability_grants",
  "service identities must have tenant-scoped capability grants",
);
requireFragment(
  "migrations/0027_snowman_workforce_request_contract.sql",
  "request_contract_sha256",
  "workforce idempotency must bind the complete canonical request contract",
);
requireFragment(
  "desktop/src-tauri/src/mesh_llm/transport_policy.rs",
  'None | Some("") | Some("0") => Ok(IrohRelayMode::Disabled)',
  "public mesh relays must default off",
);
requireFragment(
  "desktop/src-tauri/src/mesh_llm/transport_policy.rs",
  "public mesh relays are disabled",
  "public mesh relay shorthand must fail closed",
);

const releaseTauri = JSON.parse(read("desktop/src-tauri/tauri.conf.json"));
const devTauri = JSON.parse(read("desktop/src-tauri/tauri.dev.conf.json"));
if (releaseTauri.productName !== identity.command_center_name) {
  failures.push("desktop release product name differs from product/identity.json");
}
if (releaseTauri.identifier !== identity.desktop_bundle_id) {
  failures.push("desktop release bundle id differs from product/identity.json");
}
if (devTauri.identifier !== identity.desktop_dev_bundle_id) {
  failures.push("desktop dev bundle id differs from product/identity.json");
}
requireFragment(
  "deploy/charts/buzz/values.yaml",
  `repository: ${identity.container_image}`,
  "relay image differs from product/identity.json",
);
requireFragment(
  "deploy/charts/buzz-push-gateway/values.yaml",
  `repository: ${identity.push_gateway_image}`,
  "push image differs from product/identity.json",
);
requireFragment(
  "deploy/compose/compose.yml",
  "SNOWMAN_COMMAND_CENTER_IMAGE:?set a Snowman-owned digest-pinned image",
  "Compose must not have an upstream or mutable image fallback",
);

if (failures.length > 0) {
  console.error("Snowman production-boundary check failed:\n");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `Snowman production-boundary check passed for ${runtimeAuthorityFiles.length} authority files.`,
);
