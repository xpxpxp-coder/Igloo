# Snowman supply chain and launch evidence

## Immutable release artifact set

The Command Center image build emits maximum BuildKit provenance and an image
SBOM. Deployment still accepts only the Snowman workload-account ECR repository
and an `@sha256:` reference. Tags are discovery labels, never deployment
authority. The ECR repository is KMS encrypted, immutable-tagged,
Terraform-destroy protected, and its repository policy denies image deletion
or a tag-mutability downgrade.

Before a staging verification window, normalize and retain these six files:

1. the resolved OCI image-index manifest and platform count;
2. the CycloneDX or SPDX JSON SBOM;
3. provenance verification bound to the current approved repository
   (`xpxpxp-coder/Igloo`, or `snowman-ai-org/snowman-command-center` after the
   planned ownership migration), the exact commit,
   image digest, and Snowman GitHub builder identity;
4. KMS signature verification bound to the exact release-signing key and image;
5. the completed vulnerability report with current scanner database time and
   zero unresolved high or critical findings; and
6. a dependency/license inventory in which every retained package notice has a
   digest and no dependency has a missing license classification.

`scripts/verify-snowman-release-artifacts.mjs <descriptor.json>` reads those
local files, rejects symlinks, oversized files, digest mismatches, secret/raw
data keys, mutable image references, incomplete notices, unverifiable
provenance/signatures, or high/critical findings, and prints only a
metadata-only digest map. The descriptor schema is
`snowman.release-artifact-set.v1`; its `artifacts` object has exactly
`image_manifest`, `sbom`, `provenance`, `signature_verification`,
`vulnerability_report`, and `license_notices` bindings, each with `path` and
`sha256`.

The six source files, verifier output, Terraform plan JSON summary, and final
launch manifest must be copied to the Snowman audit bucket with KMS encryption
and Object Lock. Record exact `VersionId` values. A GitHub artifact, mutable S3
URI, build log, ECR scan status, or successful CI badge is not retention proof.

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
Terraform plan, telemetry destinations, confirmed alert subscription, and 18
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

The added controls are image-signature verification, license-notice retention,
encrypted backup/PITR posture, clean-target migration/restore rehearsal, and
separate meeting-media, orchestration, provider-egress, and dormant-plan
evidence.

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

## Dormant staging plan bundle

The first reviewed plan keeps all desired counts at zero and keeps meeting,
orchestration, provider, workforce, and external ingress/egress switches off.
Its evidence bundle contains the exact Terraform/provider-lock and plan
digests; source and ECR image digests; the release-artifact verifier digest map;
outputs proving zero tasks, unexpected-running alarms, encrypted retained
backups, audit Object Lock, and the monthly budget; and a pending-control
inventory that never labels an unexecuted live drill as pass. Only a later,
separately reviewed staging plan may open a bounded verification window, and it
must return every service and network switch to this dormant baseline.
