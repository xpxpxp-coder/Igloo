# Snowman PostgreSQL adversarial authority proof

This proof exercises the PostgreSQL invariants beneath Snowman's newest
governed authority paths without AWS, provider APIs, Docker, or shared test
schemas. It covers migrations 0049–0055 and their prerequisites on both a
fresh install and a populated 0048 upgrade.

The test creates a unique schema for every case and pins `search_path` on every
pooled connection. It never drops or resets `public`, so parallel CI workers
and developer databases remain isolated.

## Covered adversarial cases

- fresh migration and populated 0048-to-latest upgrade;
- wrong-tenant references and same-UUID collisions through composite keys;
- serializable aggregate model-budget reservation and exact replay/conflict;
- concurrent tool-receipt sequence collision (exactly one append wins);
- orchestration task/dependency foreign-key ordering;
- occurrence materialization, dispatch leasing, immediate cancellation
  generation fencing, and rejection of stale delivery/terminal receipts;
- meeting cancellation revision fencing and post-cancel reschedule denial;
- audit checkpoint trigger enforcement plus a narrow role that can append and
  read checkpoints but cannot update evidence or read collaboration events.

The test intentionally uses metadata and digests only. It does not contain raw
prompts, client records, mail, transcripts, meeting coordinates, credentials,
provider payloads, or external endpoints.

## Local or CI command

Provision an empty PostgreSQL database whose test principal can create schemas.
The audit-role case additionally requires `CREATEROLE` (or an equivalent CI
admin principal):

```bash
export BUZZ_TEST_DATABASE_URL='postgres://USER:PASSWORD@HOST:5432/DATABASE'
cargo test -p buzz-db --test snowman_authority_postgres -- --include-ignored
```

Run only the schema-safe cases when the CI principal cannot administer roles:

```bash
cargo test -p buzz-db --test snowman_authority_postgres -- \
  --include-ignored --skip checkpoint_tables_are_trigger_and_role_enforced_append_only
```

The normal no-infrastructure compile gate remains:

```bash
cargo test -p buzz-db --test snowman_authority_postgres --no-run
```

## Staging evidence

Before production activation, rerun the complete ignored test against a
disposable PostgreSQL database built from the exact release image/toolchain,
retain the test log and migration hashes, and then run the corresponding
service-level UAT with private Snowman identities. Passing this proof does not
substitute for AWS role, KMS, backup/restore, or provider-adapter UAT.
