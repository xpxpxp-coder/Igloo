# Snowman supply chain and launch evidence

## Production artifact path

Production images live only in the exact workload account's
`snowman-command-center` ECR repository. Terraform creates it with immutable
tags, KMS encryption, push scanning, no force-delete behavior, and a dedicated
asymmetric Snowman release-signing KMS key. ECS inputs accept only the exact
Snowman ECR repository pinned by `sha256` digest.

The current GitHub container workflow is a development/upstream-compatible
publisher and is not a production deployment authority. A production release
job must use a Snowman GitHub OIDC identity to assume a narrowly scoped AWS
build role, build from a reviewed immutable commit/tag, push by digest to this
ECR repository, create an SPDX or CycloneDX SBOM, record provenance and
dependency/license notices, scan the final digest, and sign the digest with the
Snowman KMS key. It must not use a public transparency log, Block registry,
Block signer, mutable tag, exported private key, long-lived AWS key, or runtime
download. Build-time upstream downloads are quarantined inputs; the retained
digest and reports are Snowman-owned.

The launch policy is zero unresolved critical and high findings. An exception
requires a separately signed risk decision and a future schema/policy change;
free-form exceptions cannot make the current manifest pass.

## Evidence manifest

`snowman.launch-evidence.v1` is control metadata only. It binds the exact source
commit, ECR digest, SBOM, provenance, KMS signature bundle, vulnerability scan,
Terraform plan, telemetry destinations, confirmed alert subscription, and ten
current version-bound control reports:

- tenant isolation;
- telemetry redaction;
- SLO and alert delivery;
- PostgreSQL PITR restore;
- Valkey snapshot restore;
- S3 object-version restore;
- audit checkpoint recovery;
- dormant ECS rollback;
- cost controls; and
- supply-chain policy.

Run:

```text
node scripts/verify-snowman-launch-evidence.mjs /path/to/manifest.json
```

The command prints a digest-only Terraform projection after validation. Store
the exact manifest bytes in the audit Object Lock bucket and retain the returned
S3 version ID. Terraform accepts only that digest metadata; evidence bodies and
credentials never enter state. Evidence is rejected if older than 31 days,
expired, outside the Snowman audit bucket, not bound to a version ID, missing a
required pass, linked to a non-Snowman telemetry exporter, or carrying common
secret/raw-data fields.

Production additionally requires the digest of the sole-founder operator's
final activation acceptance. Staging manifests require no final acceptance and
must encode that field as null. This preserves the final human gate without
inventing a multi-person internal process.

The current ECS services retain their source-level hard-dormant preconditions.
The new evidence preflight is necessary but not sufficient to activate them;
those locks are lifted only in the deliberate staged-UAT/production activation
change after all remaining product gates pass.
