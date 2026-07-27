# Snowman private agent job broker

Status: source service, shared contracts, durable schema, issuance function,
dedicated database-role bootstrap, KMS-encrypted runtime-secret substrate, and
local contract/IaC tests implemented; AWS service deployment, coordinator,
action tools, model authorization, and staged proof remain.

## Boundary

`snowman-agent-broker` is a separate private service, not a relay route. It has
no Nostr, collaboration, browser, connector, arbitrary object-store, Analyst
dataset, or model-provider API. The agent sandbox can reach it only through the
dedicated broker security group already defined in `infra/aws`.

The shared `snowman-agent-contract` crate binds every snapshot and receipt to:

- one tenant UUID and workspace UUID;
- one workforce request, task, service identity, and fenced lease generation;
- one digest-reviewed runtime and evaluated model catalog ID;
- one classification, sorted exact capability set, deadline, and token/cost
  budget; and
- one minimized system-policy and request/evidence-reference projection.

Raw Aptive datasets, rows, transcripts, provider URLs, relay keys, AWS
credentials, connector credentials, and provider credentials are prohibited.

## Runtime protocol

The trusted coordinator calls the library-only `issue_job` function after it
claims a live workforce task. Issuance is idempotent for the exact job,
snapshot, token digest, task, and generation; a different retry conflicts.
The opaque token is stored only as SHA-256 and is delivered to the one-shot
task as a container override.

The HTTP service exposes only:

- `GET /v1/tenants/{tenant_id}/jobs/{job_id}/snapshot`;
- `POST /v1/tenants/{tenant_id}/jobs/{job_id}/started`; and
- `POST /v1/tenants/{tenant_id}/jobs/{job_id}/result`.

The token is compared in constant time. Snapshot bytes are returned with their
stored digest and `no-store`. Start and result receipts require an exact
idempotency key, schema, snapshot digest, job/generation/runtime/model, bounded
clock, state transition, and byte ceiling. Successful results are restricted
to final-answer text and the task token budgets; failure receipts accept only a
stable non-sensitive code. Lost-response retries succeed only when the exact
receipt digest matches. Terminal jobs cannot read the snapshot again.

The serving broker database identity is verified as exact-role,
connect/usage-only, no-DDL, and `SELECT`/`UPDATE` only on
`snowman_agent_jobs`. The general relay runtime role is explicitly revoked from
that table so the public/collaboration process cannot mint, read, or alter agent
job authority.

## Remaining activation gates

- Run and prove the now-defined broker-role/secret bootstrap, provision the
  separate coordinator role, and add the dormant broker ECS service/internal
  TLS listener with its exact security groups.
- Implement the coordinator's exact ECS `RunTask`/`StopTask` authority, random
  token generation, crash reconciliation, cancellation, expiration, and purge.
- Add capability-specific action endpoints and MCP tools. Every action must
  recheck the active lease, approval, destination, canonical digest, and spend;
  arbitrary shell/network access is not an action capability.
- Add a separate, short-lived agent principal accepted by the Snowman model
  gateway. The job token must never become a model token or direct provider
  credential.
- Append externally checkpointed audit evidence and forward accepted work
  products into the governed artifact/evidence lifecycle.
- Run live cross-tenant, replay, expiration, lost-response, prompt-injection,
  output-retention, credential-exfiltration, and no-egress staging tests.

Until these pass, the new service and all agent task definitions remain hard
dormant and Snowman 360 is not production-ready.
