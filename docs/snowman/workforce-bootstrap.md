# Governed workforce bootstrap

Status: implemented and locally validated in source; a live one-shot staging
run and database assertions remain required.

The one-shot `snowman-bootstrap` task can now reconcile the complete initial
service workforce without placing private keys in Terraform, task-definition
JSON, source control, or logs. Terraform constructs a non-secret, tenant-scoped
manifest from the exact runtime profiles and evaluated model catalog. The task:

1. creates or verifies the exact Snowman community ID/host;
2. validates one distinct lead, governed analyst, client-delivery specialist,
   and quality/risk reviewer plus separately scoped scheduler, recurring
   trigger, and reminder identities;
3. refuses operator-supplied capability lists and derives an exact allowlist
   from each specialist role;
4. generates one Nostr key per service identity only when its exact Snowman AWS
   Secrets Manager container has no value, preserving it on idempotent reruns;
5. writes the common team map into worker secrets, including optional model
   overrides that must match a role-suited evaluated route;
6. binds only each generated public key in the tenant database, revokes stale
   bootstrap-owned service identities/bindings and undesired grants, refuses an
   active foreign provisioning authority, and never persists a private key;
7. activates only catalog routes whose gateway is an exact lower-case Snowman
   HTTPS origin and whose evaluation digest, time, classifications, role fit,
   quality, latency, context, and cost limits pass validation; and
8. reconciles and verifies distinct least-privilege database logins and runtime
   secrets for relay, broker, coordinator, model gateway, audit checkpoint,
   orchestration, meeting media, and the exact `snowman_provider_egress` role;
   the provider role starts tenant-unbound with FORCE-RLS enforcement and has no
   collaboration, audit, agent-job, raw-meeting, or tool-intent access; and
9. records a secret-free SHA-256 manifest receipt with identity/model counts.

The bootstrap task role can read the RDS-managed master secret, reconcile the
exact service database runtime secrets, and read/write only the identity secrets
named by the Terraform-generated manifest. Runtime execution roles can read only
their own secret. The task has no public IP or internet route. Existing random
database passwords are preserved on idempotent reruns; generated/serialized
passwords are zeroized after their Secrets Manager versions are written.

Rerunning bootstrap deliberately treats the reviewed manifest as the source of
truth. It can reactivate a manifest-listed service identity, so it is a manual
one-shot operator action—not a recurring controller. Emergency revocation
therefore remains effective unless an operator explicitly reruns the same
approved manifest.

Before activation, staging must prove fresh bootstrap, exact rerun, a malformed
manifest denial, a duplicate-key/identity denial, removed-capability revocation,
removed-model retirement, secret-version preservation, cross-tenant denial,
and log scanning for key or client-data leakage. The retained evidence is the
task definition/image digest, RunTask identity, manifest digest, secret version
IDs (never values), database receipt, assertions over active bindings/grants and
routes, and the stopped-task result.
