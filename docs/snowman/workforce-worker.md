# Snowman workforce worker

Status: implemented and unit-tested in source; AWS deployment and staged runtime
proof remain required.

`snowman-workforce-worker` is the durable execution process for the governed AI
team. One process owns exactly one tenant-bound Nostr service identity. It has no
shell, filesystem, browser, arbitrary tool, direct database, object-store, or
vendor-model access.

## Execution contract

1. Claim only a task assigned to the authenticated service identity using a
   fresh NIP-98 assertion and a retry-safe `claim_id`.
2. Validate the complete lease envelope, Snowman model route, classification,
   budgets, artifact contract, context coordinates, and identity before use.
3. For the lead task, submit a deterministic three-agent DAG: governed analyst,
   client-delivery builder, and independent quality/risk reviewer. Each task has
   a distinct service identity. The reviewer depends on every producer.
4. Let the relay policy kernel select the highest-ranked evaluated model per
   role and classification. Optional configured model IDs are proposals only;
   the relay rejects any override not in its active tenant catalog.
5. For specialist tasks, submit the exact allowlisted capability, selected model
   ID, delegated agent ID, role, artifact contract, task cost/token ceilings,
   safety/approval decision, digest-only dependency context, stable
   request-derived timestamps, and bounded instruction through the private
   Analyst 360 KMS boundary. No model endpoint crosses that boundary.
6. Heartbeat the fenced task while reading the exact KMS-signed, tenant-scoped
   Analyst status. Never complete on acceptance alone.
7. On an artifact-bearing, digest-verified success, publish a metadata-only
   context packet and finish with immutable `analyst360:sha256:` coordinates.
   Failure/cancellation/expiry records only a bounded machine code and digest.

Dependency scheduling now adds the single digest-bound context handoff emitted
by each successful prerequisite to the downstream lease. The default team
reserves two of the 64 context slots for these handoffs, so the delivery agent
receives the analyst result and the independent reviewer receives both producer
results without copying artifact bodies into Command Center storage.

Stable downstream command IDs and request-derived timestamps make a worker
crash/re-lease an exact Analyst idempotent replay rather than a second logical
job. No objective or artifact body is written to worker logs.

## Required environment

| Variable | Purpose |
| --- | --- |
| `SNOWMAN_WORKFORCE_RELAY_URL` | Exact tenant Snowman private relay HTTPS origin. |
| `SNOWMAN_WORKFORCE_NOSTR_PRIVATE_KEY` | Per-worker service key, injected from Snowman AWS Secrets Manager. |
| `SNOWMAN_WORKFORCE_IDENTITY_ID` | Exact tenant-local workforce identity UUID bound to that public key. |
| `SNOWMAN_WORKFORCE_TEAM_IDENTITIES_JSON` | Distinct analyst/delivery/reviewer identity UUIDs and optional model overrides. |
| `SNOWMAN_ANALYST_ENDPOINT` | Exact private Analyst 360 Snowman HTTPS origin. |
| `SNOWMAN_ANALYST_SERVICE_PRINCIPAL` | Analyst-bound service principal. |
| `SNOWMAN_ANALYST_SIGNING_KEY_ARN` | Asymmetric KMS request-signing key. |
| `SNOWMAN_ANALYST_TENANT_ID` | Analyst tenant/client binding. |
| `SNOWMAN_ANALYST_CLIENT_ID` | Must equal the tenant ID in v1. |
| `SNOWMAN_ANALYST_PROJECT_ID` | Exact Analyst project binding. |

The team JSON shape is:

```json
{
  "governed_analyst": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  "client_delivery": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  "quality_risk_reviewer": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  "model_overrides": {
    "governed_analyst": null,
    "client_delivery": null,
    "quality_risk_reviewer": null
  }
}
```

An omitted/null model invokes automatic best-fit routing. A string requests that
exact model but never bypasses the evaluated catalog.

## Remaining production gates

- Build capability-specific Analyst job executors that revalidate `model_id`
  against the Snowman model catalog, produce immutable artifacts, and publish
  accurate token/cost receipts. Command acceptance and polling are implemented;
  queued jobs are not yet executed by this worker.
- Add ECS task/service definitions with one task role and Secrets Manager secret
  per service identity, private Analyst routing, and no NAT/internet egress.
- Add a scheduler/recovery service, task dead-letter policy, runtime metrics and
  alarms, graceful draining, and bounded concurrency.
- Prove crash/re-lease idempotency, KMS/Analyst degradation, cancellation,
  approval waits, cross-tenant denial, artifact authority, budget exhaustion,
  backup/restore, and zero-external-egress behavior in staging.

Until those gates pass, the worker is a compiled source implementation, not a
production-readiness claim.
