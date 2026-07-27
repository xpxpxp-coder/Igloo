# Analyst 360 event and receipt boundary

Status: source foundation implemented; private AWS deployment and staged proof
remain required.

The Command Center and Analyst 360 remain separate security and data planes.
Analyst owns governed query execution, evidence, memory, recommendations,
decisions, outcomes, client data, and artifact bytes. The Command Center stores
only minimized coordination status and immutable Analyst-authoritative artifact
references. Neither service reads or shares the other's Postgres, Redis/Valkey,
S3, secrets, or KMS signing authority.

## Private ingress

`POST /internal/snowman/v1/analyst-events` accepts one
`snowman.command-center.v1` lifecycle event. The production route is disabled
unless `SNOWMAN_ANALYST_EVENT_API_ENABLED=true`; it must be exposed only by a
separately addressed private integration service, never the public relay task.
The request's `Host` resolves the Command Center community before any contract
scope is accepted.

An active `snowman_analyst_integrations` row binds exactly one community to:

- the Analyst service principal and request-verification KMS key ARN;
- the Analyst tenant, client, and project identifiers;
- the Command Center receipt-signing KMS key ARN; and
- the receiver service identity recorded in receipts.

## Exact authentication and replay defense

Analyst signs a canonical `snowman.service-request.v1` document with
RSASSA-PSS-SHA-256 in AWS KMS. The signed fields are the exact method, request
target, operation, principal, KMS key ARN, timestamp, random nonce, and canonical
body SHA-256. The receiver rejects missing or unknown authority, stale or future
timestamps, key/principal mismatch, invalid signatures, and nonces already
consumed for that community and service.

Signature verification uses AWS KMS `Verify`; no private key material enters the
relay. Nonce consumption and event acceptance commit together. The assertion
window is short, while consumed nonces remain in the replay ledger for bounded
operational retention.

## Minimized event contract

The strict JSON parser rejects unknown fields. Allowed content is limited to:

- event, command, correlation, tenant, client, and project identifiers;
- event timestamp, command-local sequence, and an allowlisted lifecycle status;
- a bounded failure code only for failed events; and
- at most 50 content-addressed artifact references whose authority is
  `analyst360` and whose classification and digest are validated.

The event contains no query text, prompt, transcript, result rows, credentials,
artifact bytes, destination URL, or arbitrary metadata map. Tenant/client/project
values must exactly match the host-derived community binding. The producer's
`event_sha256` is recomputed over the canonical event excluding that digest, and
the complete canonical payload digest is recorded separately.

## Idempotency and signed receipt

The `(community_id, event_id)` key is idempotent only when both stored digests
match. Reuse with different content fails. `(community_id, command_id,
sequence)` also prevents ambiguous histories. After durable acceptance, the
Command Center signs a canonical receipt digest using a distinct receipt-only
KMS key and persists the first successful signature before returning it.

The receipt binds the event identifier, receiver service/key, receive time, and
exact payload SHA-256. Analyst can verify it with KMS and records only the exact
receipt matching its leased outbox delivery. A KMS signing outage does not lose
an already accepted event; retrying the same event with a fresh assertion
completes or returns the durable receipt.

## Deployment and acceptance gates

Production requires all of the following evidence:

1. Dedicated Analyst request-signing and Command Center receipt-signing KMS keys
   with non-overlapping least-privilege IAM roles and CloudTrail evidence.
2. Private Snowman AWS DNS/TLS and network paths with no direct internet or Block
   endpoint, plus security-group and egress-denial proof.
3. Seeded tenant bindings through an audited administrative path; application
   requests cannot select or mutate their binding.
4. Adversarial two-tenant tests for host spoofing, scope substitution, nonce
   replay, event-ID conflict, sequence collision, artifact authority, unknown
   fields, malformed canonicalization, key substitution, and receipt forgery.
5. Analyst outbox retry/dead-letter delivery, receiver recovery, KMS degradation,
   backup/restore, metrics/alerts, and full command-to-event correlation proof.

The outbound half is implemented in `crates/snowman-analyst-client`. Workers can
submit only the six allowlisted v1 Analyst capabilities, with
tenant/client/project and delegated-agent binding, one-time exact-body AWS KMS
assertions, no ambient proxy or redirect handling, bounded responses, and local
validation of Analyst's receipt and initial lifecycle-event digests. It receives
no Analyst database, cache, object-store, or client-data credential.

Until private routing, principal/key provisioning, capability-specific workers,
and adversarial staged proof pass, this is a compiled application boundary
rather than a production-ready integration.
