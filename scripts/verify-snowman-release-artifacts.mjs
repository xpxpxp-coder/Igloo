#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const KMS_KEY = /^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key\/[0-9a-fA-F-]{36}$/;
const IMAGE = /^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\/snowman-command-center@sha256:([0-9a-f]{64})$/;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const ARTIFACT_NAMES = Object.freeze([
  "image_manifest",
  "license_notices",
  "provenance",
  "sbom",
  "signature_verification",
  "vulnerability_report",
]);
const FORBIDDEN_KEY = /(?:^|_)(?:access_?token|authorization|client_?secret|credential|password|private_?key|raw_?(?:content|data|email|row|transcript)|refresh_?token|secret)(?:$|_)/i;

function fail(message) {
  throw new Error(message);
}

function object(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${path} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, path) {
  const actual = Object.keys(object(value, path)).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${path} keys must be exactly: ${wanted.join(", ")}`);
  }
}

function noSensitiveKeys(value, path = "document") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => noSensitiveKeys(item, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEY.test(key)) fail(`${path}.${key} is prohibited in release evidence`);
    noSensitiveKeys(child, `${path}.${key}`);
  }
}

function readBoundArtifact(baseDirectory, binding, name) {
  exactKeys(binding, ["path", "sha256"], `descriptor.artifacts.${name}`);
  if (typeof binding.path !== "string" || binding.path.length === 0 || binding.path.includes("\0")) {
    fail(`descriptor.artifacts.${name}.path is invalid`);
  }
  if (typeof binding.sha256 !== "string" || !SHA256.test(binding.sha256)) {
    fail(`descriptor.artifacts.${name}.sha256 is invalid`);
  }
  const path = resolve(baseDirectory, binding.path);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${name} must be a regular non-symlink file`);
  if (stat.size < 2 || stat.size > MAX_ARTIFACT_BYTES) fail(`${name} has an invalid bounded size`);
  const real = realpathSync(path);
  if (real !== path) fail(`${name} must not traverse a symlink`);
  const bytes = readFileSync(real);
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== binding.sha256) fail(`${name} digest does not match its descriptor`);
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    fail(`${name} must be valid JSON: ${error.message}`);
  }
  noSensitiveKeys(document, name);
  return { bytes, digest, document };
}

function requireImageBinding(document, schema, imageUri, imageDigest, path) {
  if (document.schema_version !== schema || document.image_uri !== imageUri || document.image_digest !== imageDigest) {
    fail(`${path} is not bound to the exact image`);
  }
}

export function verifyReleaseArtifacts(descriptor, descriptorPath) {
  exactKeys(
    descriptor,
    ["artifacts", "image_uri", "kms_signing_key_arn", "schema_version", "source_commit_sha", "source_repository"],
    "descriptor",
  );
  if (descriptor.schema_version !== "snowman.release-artifact-set.v1") {
    fail("descriptor.schema_version is invalid");
  }
  if (descriptor.source_repository !== "snowman-ai-org/Igloo") {
    fail("descriptor.source_repository must be snowman-ai-org/Igloo");
  }
  if (typeof descriptor.source_commit_sha !== "string" || !COMMIT.test(descriptor.source_commit_sha)) {
    fail("descriptor.source_commit_sha is invalid");
  }
  const imageMatch = typeof descriptor.image_uri === "string" && descriptor.image_uri.match(IMAGE);
  if (!imageMatch) fail("descriptor.image_uri must be the immutable Snowman ECR image");
  if (typeof descriptor.kms_signing_key_arn !== "string" || !KMS_KEY.test(descriptor.kms_signing_key_arn)) {
    fail("descriptor.kms_signing_key_arn is invalid");
  }
  const imageDigest = imageMatch[1];
  exactKeys(descriptor.artifacts, ARTIFACT_NAMES, "descriptor.artifacts");
  const baseDirectory = dirname(resolve(descriptorPath));
  const artifacts = Object.fromEntries(
    ARTIFACT_NAMES.map((name) => [
      name,
      readBoundArtifact(baseDirectory, descriptor.artifacts[name], name),
    ]),
  );

  const manifest = artifacts.image_manifest.document;
  requireImageBinding(
    manifest,
    "snowman.image-manifest-verification.v1",
    descriptor.image_uri,
    imageDigest,
    "image_manifest",
  );
  if (manifest.media_type !== "application/vnd.oci.image.index.v1+json" || manifest.platform_count < 1) {
    fail("image_manifest must verify a non-empty OCI image index");
  }

  const provenance = artifacts.provenance.document;
  requireImageBinding(
    provenance,
    "snowman.provenance-verification.v1",
    descriptor.image_uri,
    imageDigest,
    "provenance",
  );
  if (
    provenance.verified !== true ||
    provenance.source_repository !== descriptor.source_repository ||
    provenance.source_commit_sha !== descriptor.source_commit_sha ||
    provenance.build_parameters_redacted !== true ||
    typeof provenance.builder_identity !== "string" ||
    !provenance.builder_identity.startsWith("https://github.com/snowman-ai-org/")
  ) {
    fail("provenance is not a verified Snowman source/build binding");
  }

  const signature = artifacts.signature_verification.document;
  requireImageBinding(
    signature,
    "snowman.kms-image-signature-verification.v1",
    descriptor.image_uri,
    imageDigest,
    "signature_verification",
  );
  if (signature.verified !== true || signature.kms_signing_key_arn !== descriptor.kms_signing_key_arn) {
    fail("signature_verification did not verify the exact KMS key");
  }

  const vulnerability = artifacts.vulnerability_report.document;
  requireImageBinding(
    vulnerability,
    "snowman.image-vulnerability-report.v1",
    descriptor.image_uri,
    imageDigest,
    "vulnerability_report",
  );
  if (
    vulnerability.scan_complete !== true ||
    vulnerability.unresolved_critical_findings !== 0 ||
    vulnerability.unresolved_high_findings !== 0 ||
    typeof vulnerability.scanner_database_updated_at !== "string" ||
    !Number.isFinite(Date.parse(vulnerability.scanner_database_updated_at))
  ) {
    fail("vulnerability_report is incomplete or has unresolved high/critical findings");
  }

  const sbom = artifacts.sbom.document;
  const cyclonedx = sbom.bomFormat === "CycloneDX" && typeof sbom.specVersion === "string";
  const spdx = typeof sbom.spdxVersion === "string" && sbom.spdxVersion.startsWith("SPDX-");
  if ((!cyclonedx && !spdx) || !Array.isArray(sbom.components ?? sbom.packages)) {
    fail("sbom must be a CycloneDX or SPDX JSON document with components");
  }

  const notices = artifacts.license_notices.document;
  if (
    notices.schema_version !== "snowman.license-notice-inventory.v1" ||
    notices.source_repository !== descriptor.source_repository ||
    notices.source_commit_sha !== descriptor.source_commit_sha ||
    notices.notices_retained !== true ||
    !Array.isArray(notices.packages) ||
    notices.packages.length === 0
  ) {
    fail("license_notices is incomplete or not bound to the exact source");
  }
  for (const [index, entry] of notices.packages.entries()) {
    exactKeys(entry, ["license", "name", "notice_sha256", "version"], `license_notices.packages[${index}]`);
    if (
      !entry.name ||
      !entry.version ||
      !entry.license ||
      new Set(["NONE", "NOASSERTION", "UNKNOWN"]).has(String(entry.license).trim().toUpperCase()) ||
      typeof entry.notice_sha256 !== "string" ||
      !SHA256.test(entry.notice_sha256)
    ) {
      fail(`license_notices.packages[${index}] is incomplete`);
    }
  }

  return {
    schema_version: "snowman.release-artifact-digests.v1",
    source_commit_sha: descriptor.source_commit_sha,
    container_image: descriptor.image_uri,
    image_digest: imageDigest,
    artifacts: Object.fromEntries(ARTIFACT_NAMES.map((name) => [name, artifacts[name].digest])),
    control_metadata_only: true,
  };
}

function main() {
  const path = process.argv[2];
  if (!path || process.argv.length !== 3) {
    console.error("usage: verify-snowman-release-artifacts.mjs <descriptor.json>");
    process.exitCode = 2;
    return;
  }
  try {
    const descriptorPath = resolve(path);
    const descriptor = JSON.parse(readFileSync(descriptorPath, "utf8"));
    process.stdout.write(`${JSON.stringify(verifyReleaseArtifacts(descriptor, descriptorPath))}\n`);
  } catch (error) {
    console.error(`release artifacts rejected: ${error.message}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) main();
