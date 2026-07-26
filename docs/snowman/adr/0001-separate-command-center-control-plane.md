# ADR 0001: Keep the Snowman Command Center separate from Analyst 360

- Status: Accepted
- Date: 2026-07-25
- Decision owners: Snowman AI sole-founder operator; implementation evidence is automated where possible

## Context

Igloo/Buzz is a collaboration, realtime event, and agent-operations platform.
Analyst 360 is the governed client-data, evidence, query, memory,
recommendation, decision, and outcome authority. Sharing their Postgres, Redis,
or object stores would collapse two security boundaries, enlarge the blast
radius of the high-risk agent execution plane, and make Aptive data minimization
materially harder to prove.

## Decision

Run the Snowman Command Center and Analyst 360 as separately deployed services
with separate databases, caches, buckets, KMS keys, task roles, secrets, backup
policies, network policy, and operational telemetry.

Integrate them through a least-privilege, versioned Snowman gateway and event
adapter. Allowed integration payloads are:

- tenant and workspace identifiers from a server-controlled mapping;
- idempotent command requests with actor/service identity, requested capability,
  policy context, expiry, correlation ID, and signed request digest;
- job lifecycle status and bounded/redacted progress;
- citation and evidence manifests;
- recommendation, decision, and outcome lifecycle events;
- immutable artifact references carrying content digest, media type, size,
  classification, retention class, and authority URI;
- append-only receipt metadata sufficient to prove who requested, authorized,
  executed, and observed an operation.

The integration does not transfer raw client datasets, Aptive source rows,
unredacted transcripts, database credentials, or unrestricted query capability.
Analyst 360 remains the only authority that executes governed client-data
queries and resolves evidence artifacts.

All production endpoints and infrastructure are Snowman-controlled. The runtime
must not contact Block relays, registries, update services, push gateways,
pairing services, downloads, telemetry, or other upstream-operated surfaces.
External processors such as a hosted model API are disabled unless an explicit,
audited connector policy names the provider, permitted data classes, purpose,
tenant, retention terms, and approval. Source provenance links and protocol
identifiers are not runtime network authority.

## Identity model

Workforce authentication enters through Snowman-approved OIDC and binds a human
subject to one or more cryptographic relay identities. The binding, tenant role,
capabilities, session/device state, authentication strength, and revocation
status are evaluated before Nostr scopes are issued. Nostr signatures remain the
signed-action mechanism; key possession alone is not workforce authorization.

Every agent/runtime/workspace receives a separate service identity and
short-lived credential. Agent capabilities are deny-by-default and cannot exceed
the authorizing human or service policy. High-impact capabilities require an
identity-bound approval record and are not conveyed as ambient shell authority.

## Evidence integrity

Both services create local append-only receipts. Cross-service requests and
responses include correlation IDs and canonical payload digests. Periodic audit
checkpoints are signed by a Snowman KMS key and retained in an immutable store
outside the mutable application database. Evidence references are content
addressed and verified when resolved.

## AWS topology

The production target is an AWS-native, independently scalable command-center
stack using an ALB and WAF, ACM/Route53, ECS/Fargate unless measurements justify
another runtime, managed PostgreSQL, managed Redis/Valkey, S3 with versioning and
KMS, Secrets Manager, private networking and VPC endpoints where practical,
central logs/metrics/traces, backup/PITR, immutable digest-pinned images, SBOM and
signature verification, budgets, and scale-to-safe staging controls.

Compose remains a local/evaluation surface and is not a production topology.

## Consequences

- The command center can evolve quickly without becoming a second client-data
  authority.
- A compromise of agent tooling does not automatically grant Analyst 360 data
  access.
- Integration carries more explicit schemas, receipts, and failure handling.
- Cross-service UAT and recovery tests become mandatory launch evidence.
- Protocol names and event kinds may remain `buzz`/Nostr internally when changing
  them would break compatibility; user-facing and operator-facing product identity
  is Snowman.
