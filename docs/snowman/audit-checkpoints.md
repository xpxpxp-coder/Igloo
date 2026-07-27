# Snowman immutable audit checkpoints

## Outcome

`snowman-audit-checkpoint` closes the database-writer gap in the existing
per-community SHA-256 audit log. A one-shot, least-privilege runtime verifies
each exact tenant segment, signs a content-minimized checkpoint digest with a
dedicated asymmetric AWS KMS key, and conditionally creates a deterministic
object in the Snowman audit bucket. S3 versioning and Object Lock COMPLIANCE
retention make those signed objects the authoritative checkpoint history.

A writer that changes old `audit_log` rows can recompute the unkeyed database
chain, but cannot replace the already retained object, produce its KMS
signature, or make the next checkpoint's `previous_checkpoint_sha256` link
validate. The verifier reads object versions independently of database receipt
rows and fails on a missing tenant, duplicate sequence, sequence regression,
bad signature, predecessor mismatch, database-root mismatch, missing S3 version
ID, missing Object Lock retention, or wrong SSE-KMS key.

## Signed schema

`snowman.audit-checkpoint.v1` binds exactly:

- `community_id` and inclusive `sequence`;
- the audit row's `chain_root_sha256`;
- the preceding signed envelope's `previous_checkpoint_sha256`;
- canonical UTC `signed_at` time;
- exact image/build and applied database-schema SHA-256 digests; and
- the exact Snowman-account KMS signing-key ARN.

The envelope adds the canonical payload digest, fixed
`RSASSA_PKCS1_V1_5_SHA_256` algorithm, and KMS signature. It contains no audit
detail, event body, person, email, prompt, message, transcript, meeting
coordinate, phone number, artifact body, client row, or credential. Logs and
alerts contain only event names and bounded counts.

## Crash and replay safety

The database freezes one append-only request for `(community_id, sequence)`.
Publication uses a deterministic object key and `If-None-Match: *`. After a
conditional conflict or ambiguous S3 response, the runtime reads the exact
version and accepts it only when every byte matches the locally verified signed
envelope. Publication receipts are append-only operational evidence, but never
replace the S3 object history as authority.

The publisher first runs the full external-history verifier. It cannot create a
new anchor to paper over a prior mismatch. Exact retries do not create another
object version or another logical receipt.

## Least privilege and dormancy

The dedicated PostgreSQL login can select only `communities` and `audit_log`,
and select/insert the checkpoint request/publication tables. It has no
collaboration, workflow, workforce, model, meeting, client-data, update, delete,
truncate, schema-create, or role-create permission. Append-only triggers reject
request or receipt mutation even through a mistakenly broadened ordinary role.

The Fargate task role can list versions only below `checkpoints/`, read/create
only those objects, use the audit signing key for `Sign`/`Verify`, and use the
data key only through S3. It has no delete, retention-bypass, Object Lock
mutation, relay, Analyst 360, model, connector, or public-network permission.
The EventBridge rule is checked in `DISABLED`; enabling it requires exact image
and schema digests.

## Verification and restore

The same image provides both paths:

```text
snowman-audit-checkpoint publish
snowman-audit-checkpoint verify
```

`verify` is safe for an isolated PITR recovery database when supplied its
dedicated read/append role and the production audit bucket coordinates. It
verifies every retained checkpoint and every database interval from genesis;
it does not write AWS state. A recovery report must retain the exact object key,
version ID, signing-key ARN, build/schema digests, measured RPO/RTO, and pass or
fail outcome without checkpoint bodies or client content.

## Staged production gates

Keep the schedule disabled until all gates pass in the exact workload account:

1. Prove the KMS key is asymmetric `SIGN_VERIFY`, private material is
   non-exportable, task IAM permits only exact `Sign`/`Verify`, and verification
   still succeeds after a reviewed KMS rotation/alias transition. Rotation is a
   new key ARN; old keys remain enabled for verification through the retention
   window and the key transition is itself linked by the prior checkpoint.
2. Prove S3 versioning, COMPLIANCE Object Lock, exact SSE-KMS, public-access
   blocks, no delete/bypass permission, deterministic conditional create, and
   ambiguous-response recovery by exact version ID.
3. Publish at least two anchors for two isolated tenants; verify predecessor
   links and adversarially prove no tenant key, sequence, root, or receipt can be
   substituted across tenants.
4. Rewrite a restored copy of database audit history and recompute its keyless
   chain. Require checkpoint verification failure and monitored alert delivery.
5. Corrupt a signature, remove an object from a test bucket, create a duplicate
   sequence, use the wrong build/schema digest, and deny the wrong KMS/S3/DB
   identities. Every case must fail closed without payload bytes in logs.
6. Run PITR plus immutable object-version recovery, verify from genesis, record
   RPO/RTO and restore coordinates, then validate the launch-evidence digest.
7. Exercise schedule failure, stale-checkpoint paging, SNS delivery to the
   monitored Snowman mailbox, and the sole-founder acknowledgement path.
