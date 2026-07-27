#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { verifyReleaseArtifacts } from "./verify-snowman-release-artifacts.mjs";

const directory = mkdtempSync(join(tmpdir(), "snowman-release-artifacts-"));
const commit = "a".repeat(40);
const digest = "b".repeat(64);
const image = `111111111111.dkr.ecr.us-west-2.amazonaws.com/snowman-command-center@sha256:${digest}`;
const kms = "arn:aws:kms:us-west-2:111111111111:key/00000000-0000-0000-0000-000000000000";
const documents = {
  image_manifest: {
    schema_version: "snowman.image-manifest-verification.v1",
    image_uri: image,
    image_digest: digest,
    media_type: "application/vnd.oci.image.index.v1+json",
    platform_count: 2,
  },
  provenance: {
    schema_version: "snowman.provenance-verification.v1",
    image_uri: image,
    image_digest: digest,
    verified: true,
    source_repository: "snowman-ai-org/Igloo",
    source_commit_sha: commit,
    builder_identity: "https://github.com/snowman-ai-org/Igloo/.github/workflows/docker.yml",
    build_parameters_redacted: true,
  },
  signature_verification: {
    schema_version: "snowman.kms-image-signature-verification.v1",
    image_uri: image,
    image_digest: digest,
    verified: true,
    kms_signing_key_arn: kms,
  },
  vulnerability_report: {
    schema_version: "snowman.image-vulnerability-report.v1",
    image_uri: image,
    image_digest: digest,
    scan_complete: true,
    unresolved_critical_findings: 0,
    unresolved_high_findings: 0,
    scanner_database_updated_at: "2026-07-27T00:00:00Z",
  },
  sbom: { bomFormat: "CycloneDX", specVersion: "1.6", components: [{ name: "snowman" }] },
  license_notices: {
    schema_version: "snowman.license-notice-inventory.v1",
    source_repository: "snowman-ai-org/Igloo",
    source_commit_sha: commit,
    notices_retained: true,
    packages: [{ name: "example", version: "1.0.0", license: "Apache-2.0", notice_sha256: "c".repeat(64) }],
  },
};

const artifacts = {};
for (const [name, document] of Object.entries(documents)) {
  const bytes = Buffer.from(`${JSON.stringify(document)}\n`);
  const path = `${name}.json`;
  writeFileSync(join(directory, path), bytes);
  artifacts[name] = { path, sha256: createHash("sha256").update(bytes).digest("hex") };
}
const descriptor = {
  schema_version: "snowman.release-artifact-set.v1",
  source_repository: "snowman-ai-org/Igloo",
  source_commit_sha: commit,
  image_uri: image,
  kms_signing_key_arn: kms,
  artifacts,
};
const descriptorPath = join(directory, "descriptor.json");
writeFileSync(descriptorPath, `${JSON.stringify(descriptor)}\n`);

const result = verifyReleaseArtifacts(descriptor, descriptorPath);
assert.equal(result.container_image, image);
assert.equal(result.control_metadata_only, true);
assert.match(result.artifacts.sbom, /^[0-9a-f]{64}$/);

const vulnerable = structuredClone(descriptor);
documents.vulnerability_report.unresolved_high_findings = 1;
const vulnerableBytes = Buffer.from(`${JSON.stringify(documents.vulnerability_report)}\n`);
writeFileSync(join(directory, "vulnerability_report.json"), vulnerableBytes);
vulnerable.artifacts.vulnerability_report.sha256 = createHash("sha256").update(vulnerableBytes).digest("hex");
assert.throws(
  () => verifyReleaseArtifacts(vulnerable, descriptorPath),
  /unresolved high\/critical findings/,
);

console.log("snowman release-artifact contract passed");
