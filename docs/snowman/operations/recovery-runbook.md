# Snowman Command Center recovery and rollback runbook

The managed backup configuration and recovery evidence contracts are packaged,
but the clean-target staging restore is **not yet live-proven**. Source checks
must not be reported as a successful restore, RPO, or RTO measurement.

## Safety rules

- Restore into a newly named, isolated recovery target. Never restore over the
  only usable staging or production database, cache, bucket version, checkpoint,
  secret, or Terraform state.
- Use the exact Snowman workload account and region after a read-only caller
  identity check. Keep services dormant and public/private ingress disabled
  while integrity and tenant-isolation checks run.
- Recovery targets receive new least-privilege security groups, runtime secrets,
  and database users. Production credentials are never copied into evidence.
- Reports contain opaque IDs, timings, digests, row/object counts, and pass/fail
  results only. They do not contain client rows, prompts, messages, email,
  transcripts, meeting coordinates, artifact bodies, or secrets.
- Delete temporary recovery targets only after the evidence object is retained
  by version ID and the original service remains healthy. Deletion follows a
  separately reviewed cleanup plan; this runbook performs no automatic delete.

## PostgreSQL point-in-time recovery

1. Record the source instance ARN, latest restorable time, chosen recovery time,
   encrypted snapshot/PITR posture, engine version, KMS key ARN, and Terraform
   commit without recording connection strings.
2. Restore to a new identifier in the isolated data subnets with no application
   ingress. Do not reuse the serving secret or serving database role.
3. Run migrations in verify-only mode, audit-chain verification, tenant-scoped
   row-count/digest checks, foreign-key checks, replay/idempotency checks, and a
   metadata-only application smoke test.
4. Attempt adversarial cross-tenant reads with the recovered serving roles and
   require denial with zero returned payload bytes.
5. Record measured RPO/RTO, the selected restore timestamp, restore target ARN,
   schema/migration digest, integrity results, and cleanup plan.

### Migration and service-role rehearsal

The restored target must start at the selected backup coordinate and run the
exact immutable image's migrations without skipping, editing, or reordering a
migration. Capture the pre-migration schema digest, migration inventory digest,
post-migration schema digest, and image digest. Then verify the dedicated
`snowman_meeting_media`, `snowman_orchestration`, and
`snowman_provider_egress` login roles and their least-privilege grants before
running any service smoke test. A rehearsal fails if it needs a production
credential, grants a service role table-wide authority, mutates the source
database, or cannot replay from the same backup into a second clean target.

The immutable `migration-restore-rehearsal` report records only the target ARN,
backup coordinate, migration/schema/image digests, role names, counts, timings,
and pass/fail assertions. It must contain no SQL result rows, connection URL,
client content, or secret value.

Production acceptance requires a successful restore within the declared RTO
and an observed RPO no larger than the accepted business target. RDS retention
is 35 days in production; that configuration is not a substitute for the drill.

## Valkey recovery

Valkey is coordination state, not durable evidence authority. Restore the
latest managed snapshot to a new replication group and validate TLS/IAM
authentication, exact ACL key/channel prefixes, reconnect and resubscription,
duplicate suppression, lease expiry, and rebuild-from-PostgreSQL behavior.
No launch may depend on cache-only state surviving. Record snapshot ARN/time,
measured RPO/RTO, reconstructed subscription counts, denial tests, and cleanup.

## S3 object-version recovery

For artifacts, media, and audit checkpoints, select an exact object version and
copy it to a recovery prefix or separate recovery bucket encrypted with the
Snowman data key. Verify checksum, version ID, retention/legal-hold state,
tenant/workspace metadata, and application authorization without exposing the
body in logs. Object Lock is never bypassed for a drill. Record source and
recovered version coordinates plus digest and access-denial results.

## Audit checkpoint recovery

1. Restore PostgreSQL into the isolated recovery target and verify every
   per-tenant application hash chain from genesis.
2. Read the corresponding immutable checkpoint object by exact version ID.
3. verify its asymmetric KMS signature with the dedicated checkpoint public key,
   then compare tenant, sequence, head hash, canonicalization version, database
   backup coordinate, and signed time.
4. Demonstrate that a simulated database writer can recompute the unkeyed chain
   but cannot produce a matching later KMS-signed immutable checkpoint.
5. Fail the drill on any missing tenant, sequence regression, signature error,
   unexplained head mismatch, restore coordinate mismatch, or retention gap.

The publisher/verifier, dedicated database role, KMS/S3 task identity, dormant
schedule, immutable evidence tables, and failure alarms now exist in source.
Production activation remains blocked until the exact-account KMS rotation,
S3 Object Lock, tamper, tenant-isolation, alert-delivery, and restore drills in
`docs/snowman/audit-checkpoints.md` pass and the schedule is explicitly enabled.

## ECS rollback

Keep the prior signed digest and task definition retained. During a staged
window, exercise deployment circuit-breaker rollback, forced dependency
degradation, task termination, secret rotation, and rollback to the prior exact
digest. Verify readiness, lease fencing, no duplicate external action, no lost
terminal evidence, and restored SLOs. Return desired counts and ingress switches
to their reviewed dormant baseline after the window.

## Evidence completion

Store the redacted restore/rollback report in the Object Lock audit bucket and
retain its exact version ID. `scripts/verify-snowman-launch-evidence.mjs` will
reject launch evidence unless current `postgres-pitr-restore`,
`valkey-snapshot-restore`, `s3-version-restore`, `audit-checkpoint-recovery`, and
`dormant-rollback` reports all pass.

The launch manifest additionally requires `backup-encryption-pitr` and
`migration-restore-rehearsal`. Meeting media, orchestration, and provider
egress each require their own current staged report; a successful relay restore
does not imply that those execution planes can safely resume leases, calls,
provider requests, or lost-response reconciliation.
