#!/usr/bin/env node

import assert from "node:assert/strict";

import { REQUIRED_EVIDENCE, validateManifest } from "./verify-snowman-launch-evidence.mjs";

const now = new Date("2026-07-26T12:00:00Z");
const digest = (character) => character.repeat(64);

function manifest() {
  return {
    schema_version: "snowman.launch-evidence.v1",
    environment: "staging",
    data_classification: "control_metadata_only",
    generated_at: "2026-07-26T11:00:00Z",
    expires_at: "2026-08-02T11:00:00Z",
    source: {
      repository: "snowman-ai-org/Igloo",
      commit_sha: "a".repeat(40),
    },
    image: {
      uri: `111111111111.dkr.ecr.us-west-2.amazonaws.com/snowman-command-center@sha256:${digest("b")}`,
      sbom_sha256: digest("c"),
      provenance_sha256: digest("d"),
      manifest_sha256: digest("0"),
      signature_bundle_sha256: digest("e"),
      vulnerability_report_sha256: digest("f"),
      kms_signing_key_arn: "arn:aws:kms:us-west-2:111111111111:key/00000000-0000-0000-0000-000000000000",
      critical_findings: 0,
      high_findings: 0,
    },
    telemetry: {
      exporters: ["aws-cloudwatch"],
      alert_subscription_confirmed: true,
    },
    evidence: REQUIRED_EVIDENCE.map((controlId, index) => ({
      control_id: controlId,
      status: "pass",
      report_sha256: digest(String.fromCharCode(97 + (index % 6))),
      immutable_uri: `s3://snowman-cc-staging-audit-proof/launch/${controlId}.json?versionId=v${index}`,
      observed_at: "2026-07-26T10:00:00Z",
      expires_at: "2026-08-02T10:00:00Z",
    })),
    activation: {
      terraform_plan_sha256: digest("1"),
      operator_acceptance_sha256: null,
    },
  };
}

function validate(value) {
  const raw = Buffer.from(`${JSON.stringify(value)}\n`);
  return validateManifest(value, raw, { now });
}

const valid = manifest();
const result = validate(valid);
assert.match(result.manifest_sha256, /^[0-9a-f]{64}$/);
assert.equal(result.container_image, valid.image.uri);

const outsideExporter = structuredClone(valid);
outsideExporter.telemetry.exporters = ["https://telemetry.example.com"];
assert.throws(() => validate(outsideExporter), /outside the Snowman boundary/);

const missingRestore = structuredClone(valid);
missingRestore.evidence = missingRestore.evidence.filter(
  ({ control_id: controlId }) => controlId !== "postgres-pitr-restore",
);
assert.throws(() => validate(missingRestore), /exactly 18 required controls/);

const mutableEvidence = structuredClone(valid);
mutableEvidence.evidence[0].immutable_uri = "s3://snowman-cc-staging-audit-proof/launch/report.json";
assert.throws(() => validate(mutableEvidence), /version-bound object/);

const vulnerableImage = structuredClone(valid);
vulnerableImage.image.high_findings = 1;
assert.throws(() => validate(vulnerableImage), /zero critical and zero high/);

const unconfirmedAlerts = structuredClone(valid);
unconfirmedAlerts.telemetry.alert_subscription_confirmed = false;
assert.throws(() => validate(unconfirmedAlerts), /must be true/);

const secretBearing = structuredClone(valid);
secretBearing.telemetry.client_secret = "do-not-store-this";
assert.throws(() => validate(secretBearing), /keys must be exactly|prohibited/);

console.log("snowman launch-evidence contract passed");
