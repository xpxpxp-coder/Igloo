# Snowman private agent job broker

Status: source service, shared contracts, durable schema, issuance function,
dedicated database-role bootstrap, KMS-encrypted runtime-secret substrate,
hard-dormant private TLS ECS/NLB deployment definition, private authenticated
coordinator service and AWS substrate, and local contract/IaC tests implemented;
worker wiring/running-task reconciliation, action tools, model credentials, applied AWS
deployment, and staged proof remain.

## Boundary

`snowman-agent-broker` is a separate private service, not a relay route. It has
no Nostr, collaboration, browser, connector, arbitrary object-store, Analyst
dataset, or model-provider API. The agent sandbox reaches an internal TLS NLB
on port 443; its ingress security group accepts only the one-shot executor
security group and forwards only to the broker task on port 8080. The task can
reach only its RDS security group, private ECR/log/secret/KMS endpoints, and VPC
DNS. It has no AWS task role, public IP, NAT route, relay, Analyst, model,
object-store, connector, or public destination.

The digest-pinned Snowman Command Center image now packages the broker binary.
Its ECS execution role can pull only that exact Snowman ECR repository, write
only the broker log group, and read only the `database_url` field from the
separate KMS-encrypted broker runtime secret. TLS terminates on a protected
internal NLB with exact stage-specific split-horizon DNS and ACM certificate.
Readiness checks accept the broker's deliberate HTTP 204 response.

The shared `snowman-agent-contract` crate binds every snapshot and receipt to:

- one tenant UUID and workspace UUID;
- one workforce request, task, service identity, and fenced lease generation;
- one digest-reviewed runtime and evaluated model catalog ID;
- one classification, evidence-bearing PII prohibition/minimization result,
  sorted exact capability set, deadline, and token/cost budget; and
- one minimized system-policy and request/evidence-reference projection.

Raw Aptive datasets, rows, transcripts, provider URLs, relay keys, AWS
credentials, connector credentials, and provider credentials are prohibited.

## Runtime protocol

The trusted coordinator uses the transaction-scoped issuance function after it
validates a live workforce task. Job and launch evidence commit atomically.
Issuance now requires an active, unrevoked service identity, active capability
grants for every task capability plus `workforce.tasks.execute`, and an active
model route allowed for the specialist role and data classification. Issuance
is idempotent for the exact job,
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
`snowman_agent_jobs`. A separate coordinator role can read only workforce
authority/model policy and insert/update job, launch, and anti-replay evidence;
it cannot read collaboration events, change workforce authority, or delete
evidence. The general relay runtime role is explicitly revoked from all three
agent authority/evidence tables.

## Remaining activation gates

- Run and prove the now-defined broker/coordinator role bootstrap and dormant
  private TLS service plan.
- Promote the coordinator library into its private authenticated service and
  finish due-launch reconciliation, cancellation, expiration, terminal task
  observation, token revocation, and retention/purge evidence.
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
