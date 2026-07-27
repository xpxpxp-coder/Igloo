#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const KMS_SIGNING_KEY =
  /^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key\/[0-9a-fA-F-]{36}$/;
const SNOWMAN_IMAGE =
  /^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/snowman-command-center@sha256:([0-9a-f]{64})$/;
const APPROVED_SOURCE_REPOSITORIES = new Set([
  "xpxpxp-coder/Igloo",
  "snowman-ai-org/snowman-command-center",
]);

export const REQUIRED_EVIDENCE = Object.freeze([
  "audit-checkpoint-recovery",
  "backup-encryption-pitr",
  "cost-control",
  "dormant-rollback",
  "dormant-staging-plan",
  "image-signature-verification",
  "license-notice-retention",
  "meeting-media-runtime",
  "migration-restore-rehearsal",
  "orchestration-runtime",
  "postgres-pitr-restore",
  "provider-egress-runtime",
  "s3-version-restore",
  "slo-alert-delivery",
  "supply-chain-policy",
  "telemetry-redaction",
  "tenant-isolation",
  "valkey-snapshot-restore",
]);

const EXACT_TOP_LEVEL_KEYS = Object.freeze([
  "activation",
  "data_classification",
  "environment",
  "evidence",
  "expires_at",
  "generated_at",
  "image",
  "schema_version",
  "source",
  "telemetry",
]);

const forbiddenKey = /(?:^|_)(?:access_?token|authorization|client_?secret|credential|password|private_?key|raw_?(?:content|data|email|row|transcript)|refresh_?token|secret)(?:$|_)/i;

function fail(message) {
  throw new Error(message);
}

function requireObject(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${path} must be an object`);
  }
  return value;
}

function requireExactKeys(value, expected, path) {
  const actual = Object.keys(requireObject(value, path)).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${path} keys must be exactly: ${wanted.join(", ")}`);
  }
}

function requireString(value, path, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${path} has an invalid value`);
  }
  return value;
}

function requireTimestamp(value, path) {
  requireString(value, path, RFC3339);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) fail(`${path} is not a real RFC3339 timestamp`);
  return timestamp;
}

function checkForbiddenKeys(value, path = "manifest") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => checkForbiddenKeys(item, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (forbiddenKey.test(key)) fail(`${path}.${key} is prohibited in launch evidence`);
    checkForbiddenKeys(child, `${path}.${key}`);
  }
}

function validateImmutableEvidenceUri(uri, environment, path) {
  const prefix = `s3://snowman-cc-${environment}-audit-`;
  if (
    typeof uri !== "string" ||
    !uri.startsWith(prefix) ||
    !uri.includes("/") ||
    !/[?&]versionId=[A-Za-z0-9+/=_-]{1,1024}$/.test(uri)
  ) {
    fail(`${path} must be a version-bound object in the Snowman audit bucket`);
  }
}

function validateEvidenceItems(items, environment, nowMs) {
  if (!Array.isArray(items)) fail("manifest.evidence must be an array");
  if (items.length !== REQUIRED_EVIDENCE.length) {
    fail(`manifest.evidence must contain exactly ${REQUIRED_EVIDENCE.length} required controls`);
  }

  const seen = new Set();
  for (const [index, item] of items.entries()) {
    const path = `manifest.evidence[${index}]`;
    requireExactKeys(
      item,
      ["control_id", "expires_at", "immutable_uri", "observed_at", "report_sha256", "status"],
      path,
    );
    if (!REQUIRED_EVIDENCE.includes(item.control_id)) {
      fail(`${path}.control_id is not a required launch control`);
    }
    if (seen.has(item.control_id)) fail(`${path}.control_id is duplicated`);
    seen.add(item.control_id);
    if (item.status !== "pass") fail(`${path}.status must be pass`);
    requireString(item.report_sha256, `${path}.report_sha256`, SHA256);
    validateImmutableEvidenceUri(item.immutable_uri, environment, `${path}.immutable_uri`);
    const observedAt = requireTimestamp(item.observed_at, `${path}.observed_at`);
    const expiresAt = requireTimestamp(item.expires_at, `${path}.expires_at`);
    if (observedAt > nowMs + 5 * 60_000) fail(`${path}.observed_at is in the future`);
    if (expiresAt <= nowMs) fail(`${path}.expires_at has passed`);
    if (expiresAt <= observedAt) fail(`${path}.expires_at must follow observed_at`);
  }
}

/**
 * Validate and canonicalize a Snowman launch-evidence manifest.
 *
 * The returned digest covers the exact UTF-8 JSON bytes supplied to this
 * function. Callers must retain those same bytes as the immutable S3 object.
 */
export function validateManifest(manifest, rawBytes, options = {}) {
  requireExactKeys(manifest, EXACT_TOP_LEVEL_KEYS, "manifest");
  checkForbiddenKeys(manifest);

  if (manifest.schema_version !== "snowman.launch-evidence.v1") {
    fail("manifest.schema_version must be snowman.launch-evidence.v1");
  }
  if (!new Set(["staging", "production"]).has(manifest.environment)) {
    fail("manifest.environment must be staging or production");
  }
  if (manifest.data_classification !== "control_metadata_only") {
    fail("manifest.data_classification must be control_metadata_only");
  }

  const nowMs = options.now instanceof Date ? options.now.getTime() : Date.now();
  const generatedAt = requireTimestamp(manifest.generated_at, "manifest.generated_at");
  const expiresAt = requireTimestamp(manifest.expires_at, "manifest.expires_at");
  if (generatedAt > nowMs + 5 * 60_000) fail("manifest.generated_at is in the future");
  if (generatedAt < nowMs - 31 * 24 * 60 * 60_000) {
    fail("manifest.generated_at is older than the 31-day launch window");
  }
  if (expiresAt <= nowMs) fail("manifest.expires_at has passed");
  if (expiresAt > generatedAt + 31 * 24 * 60 * 60_000) {
    fail("manifest.expires_at exceeds the 31-day launch window");
  }

  requireExactKeys(manifest.source, ["commit_sha", "repository"], "manifest.source");
  if (!APPROVED_SOURCE_REPOSITORIES.has(manifest.source.repository)) {
    fail("manifest.source.repository is not an approved Snowman repository");
  }
  requireString(manifest.source.commit_sha, "manifest.source.commit_sha", COMMIT);

  requireExactKeys(
    manifest.image,
    [
      "critical_findings",
      "high_findings",
      "kms_signing_key_arn",
      "manifest_sha256",
      "provenance_sha256",
      "sbom_sha256",
      "signature_bundle_sha256",
      "uri",
      "vulnerability_report_sha256",
    ],
    "manifest.image",
  );
  const imageMatch = requireString(manifest.image.uri, "manifest.image.uri", SNOWMAN_IMAGE).match(
    SNOWMAN_IMAGE,
  );
  if (!imageMatch) fail("manifest.image.uri is invalid");
  for (const field of [
    "provenance_sha256",
    "manifest_sha256",
    "sbom_sha256",
    "signature_bundle_sha256",
    "vulnerability_report_sha256",
  ]) {
    requireString(manifest.image[field], `manifest.image.${field}`, SHA256);
  }
  requireString(manifest.image.kms_signing_key_arn, "manifest.image.kms_signing_key_arn", KMS_SIGNING_KEY);
  if (manifest.image.critical_findings !== 0 || manifest.image.high_findings !== 0) {
    fail("production image must have zero critical and zero high unresolved findings");
  }

  requireExactKeys(manifest.telemetry, ["alert_subscription_confirmed", "exporters"], "manifest.telemetry");
  if (manifest.telemetry.alert_subscription_confirmed !== true) {
    fail("manifest.telemetry.alert_subscription_confirmed must be true");
  }
  if (!Array.isArray(manifest.telemetry.exporters) || manifest.telemetry.exporters.length === 0) {
    fail("manifest.telemetry.exporters must name at least one Snowman-owned sink");
  }
  for (const [index, exporter] of manifest.telemetry.exporters.entries()) {
    if (
      exporter !== "aws-cloudwatch" &&
      exporter !== "aws-xray" &&
      !/^https:\/\/([a-z0-9-]+\.)*snowmanai\.org(?::[0-9]{2,5})?$/.test(exporter)
    ) {
      fail(`manifest.telemetry.exporters[${index}] is outside the Snowman boundary`);
    }
  }

  validateEvidenceItems(manifest.evidence, manifest.environment, nowMs);

  requireExactKeys(
    manifest.activation,
    ["operator_acceptance_sha256", "terraform_plan_sha256"],
    "manifest.activation",
  );
  requireString(manifest.activation.terraform_plan_sha256, "manifest.activation.terraform_plan_sha256", SHA256);
  if (manifest.environment === "production") {
    requireString(
      manifest.activation.operator_acceptance_sha256,
      "manifest.activation.operator_acceptance_sha256",
      SHA256,
    );
  } else if (manifest.activation.operator_acceptance_sha256 !== null) {
    fail("staging operator_acceptance_sha256 must be null");
  }

  const bytes = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes);
  if (bytes.length > 256 * 1024) fail("launch evidence manifest exceeds 256 KiB");
  return {
    manifest_sha256: createHash("sha256").update(bytes).digest("hex"),
    source_commit_sha: manifest.source.commit_sha,
    container_image: manifest.image.uri,
    expires_at: manifest.expires_at,
    environment: manifest.environment,
  };
}

function main() {
  const path = process.argv[2];
  if (!path || process.argv.length > 3) {
    console.error("usage: verify-snowman-launch-evidence.mjs <manifest.json>");
    process.exitCode = 2;
    return;
  }

  try {
    const raw = readFileSync(resolve(path));
    const manifest = JSON.parse(raw.toString("utf8"));
    process.stdout.write(`${JSON.stringify(validateManifest(manifest, raw))}\n`);
  } catch (error) {
    console.error(`launch evidence rejected: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
