# Governed database and runtime-key bootstrap

## Outcome and boundary

The Snowman Command Center serving relay never receives the PostgreSQL migration
identity and never runs schema DDL in the AWS runtime contract. Terraform creates
empty KMS-encrypted Secrets Manager shells and two dormant task definitions:

- `snowman-bootstrap` is a one-shot task with no service. It can read the exact
  RDS-managed master secret, read/write the exact relay-runtime secret, reach the
  private database, reconcile only the configured workforce identity secrets,
  and write migration logs. It has no NAT or public route.
- `buzz-relay` receives only the reconciled runtime database URL, stable relay
  signing key, git-hook HMAC key, and enrolled owner public key from the runtime
  secret. Its database role has DML but no database or schema creation authority.

Terraform never receives, renders, or stores the database password, relay private
key, HMAC key, or secret JSON document.

## One-shot behavior

The bootstrap binary:

1. validates the fixed runtime role name and the explicitly supplied Snowman
   owner Nostr public key;
2. reads and parses the RDS-managed secret through its task role;
3. runs the checked-in SQLx migrations;
4. creates or reconciles the serving role as `NOINHERIT`, `NOSUPERUSER`,
   `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`, and `NOBYPASSRLS`;
5. passes the password as a bound PostgreSQL setting so it does not enter SQL
   text or duration-based statement logs;
6. grants schema usage, table DML, and sequence usage while revoking database and
   schema creation;
7. generates stable relay/HMAC material only when the runtime secret has no
   current version, then preserves that material on idempotent reruns;
8. optionally applies the strict, non-secret workforce manifest, creates or
   verifies its Snowman tenant host, generates/preserves each service key only in
   its exact secret, binds public keys and fixed role capabilities, reconciles
   evaluated model routes, and records a manifest-digest receipt;
9. connects as the runtime identity and fails unless required tables and DML
   privileges exist and DDL privileges do not; and
10. writes the exact four-field JSON document to the governed runtime secret and
   logs only a success statement without secret material.

## Execution gate

The task definition deliberately omits `SNOWMAN_RELAY_OWNER_PUBKEY`. The value is
not a generic deployment default: it must be a Snowman-controlled owner public
key selected for the workforce owner binding. Supply it as a reviewed ECS
RunTask container environment override. The task does not create the human OIDC
session/binding; that remains the identity broker's job. It fails closed when
the value is missing or is not a valid Nostr public key.

When workforce profiles are configured, Terraform supplies
`SNOWMAN_WORKFORCE_BOOTSTRAP_MANIFEST` as non-secret configuration and grants
the task read/write access to only those exact identity-secret ARNs. No service
private key or provider credential appears in the manifest.

Before a live run, record the AWS caller/account, immutable image digest, task
definition revision, private subnet and security group IDs, database endpoint,
runtime secret ARN, owner binding evidence, and expected log group. Afterward,
retain the ECS stopped-task result, migration log digest, runtime-role readiness
probe, secret version ID (never the value), and database migration versions.

## Rotation and partition caveats

This task reconciles an existing secret; it does not silently rotate stable key
material. Password and relay-key rotation need a separately staged dual-identity
procedure with rollback evidence.

The checked-in database has a right-edge catch-all partition. Bootstrap currently
checks that writes remain covered, while relay startup is configured for external
partition maintenance. A recurring privileged maintenance task and a proven
catch-all split/retention procedure are still required before production. Do not
grant the serving role DDL as a shortcut.
