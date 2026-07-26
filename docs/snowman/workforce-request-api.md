# Governed workforce request API

Status: implemented source foundation; not yet staged or production-approved.

The public command-center API accepts a user objective and creates one bounded
planning task. It does not accept a caller-authored agent graph, service
identity, capability set, tool route, or model endpoint. The private
orchestrator must turn the planning artifact into a `snowman.team_plan.v1`
graph and pass that graph through the `snowman-workforce` policy kernel before
specialist tasks can be persisted or executed.

## Authentication and authority

Both routes require a tenant-host-bound NIP-98 signature, shared replay
protection, rate limiting, closed relay membership, a live Snowman human
session, an exact tenant-role match, and a fine-grained grant:

| Route | Capability | Result |
| --- | --- | --- |
| `POST /api/snowman/v1/work-requests` | `workforce.requests.create` | Idempotently accepts an objective and enqueues a capability-bounded lead planning task. |
| `GET /api/snowman/v1/work-requests/{request_id}` | `workforce.requests.read` | Returns lifecycle, task, budget, spend, and bounded hash-chain evidence metadata. |

The server derives `community_id` from the normalized request host and derives
the requester from the signed relay key's live workforce binding. Neither is a
request field. Status reads are always scoped by both derived tenant and
request ID, so the same request UUID in another tenant is not addressable.

## Request constraints

- `Idempotency-Key` is mandatory and is stored only as a SHA-256 digest.
- Reuse succeeds only for the same requester, objective, classification,
  deadline, budget ceilings, context references, and client-ready review mode;
  conflicting reuse fails closed against the canonical request-contract digest.
- The objective is bounded to 8,000 safe text bytes. Raw client extracts,
  transcripts, query results, and credentials are not valid objective content.
- Context enters only as `analyst360:sha256:<digest>` or
  `snowman:sha256:<digest>` coordinates. Raw datasets remain in Analyst 360.
- Classification is `internal`, `confidential`, or `restricted`.
- Cost, input-token, output-token, and deadline ceilings are validated before
  persistence.
- The initial task is always the configured tenant-local lead identity with
  only `workforce.plan`; arbitrary caller-supplied execution is impossible.

## Evidence and response boundary

Request acceptance and its initial task graph commit in one transaction. The
genesis `request.accepted` event includes only classification, objective digest,
and task count and begins the request-local SHA-256 hash chain. Status omits raw
objective text and requester/provider identifiers. It returns at most the newest
200 bounded events plus the total event count; event payload validation rejects
credential-like fields.

## Deployment gates

The API is absent unless `SNOWMAN_WORKFORCE_API_ENABLED=true`. Startup then
requires all of the following:

- closed membership, governed relay roles, and live workforce identity
  enforcement;
- `SNOWMAN_WORKFORCE_LEAD_IDENTITY_ID` for an active tenant-local service
  identity holding `workforce.plan`;
- `SNOWMAN_MODEL_GATEWAY_URL` on a Snowman-controlled HTTPS domain; and
- `SNOWMAN_PLANNING_MODEL_ID` from the evaluated model catalog.

The Helm chart keeps intake disabled by default until that identity and gateway
exist. AWS workers, scheduler, sandbox, private worker network deployment and
runtime proof, plan persistence, cancellation, approvals, and staged failure
evidence remain open launch gates.

## Private worker control path

Source support now exists for a separately addressed private worker service:

| Route | Behavior |
| --- | --- |
| `POST /internal/snowman/v1/workforce/tasks/claim` | Idempotently leases the next task assigned to the authenticated service identity. |
| `POST /internal/snowman/v1/workforce/tasks/{task_id}/heartbeat` | Renews only the matching live fencing generation and bearer lease. |
| `POST /internal/snowman/v1/workforce/tasks/{task_id}/spend` | Records an actor-, task-, request-, model-, and provider-receipt-bound ledger entry under hard caps. |
| `POST /internal/snowman/v1/workforce/tasks/{task_id}/finish` | Atomically records a terminal result and hash-chain evidence event under the current lease. |

Every route requires a live `service` workforce binding and the exact
`workforce.tasks.execute` capability. Task claim also rechecks all task-specific
capabilities in PostgreSQL. A worker-generated `claim_id` and a deterministic,
domain-separated relay HMAC make lost claim responses retryable without a
second lease. Lease tokens are stored only as SHA-256 digests. Spend and finish
operations are idempotent and reject stale fencing generations.

`SNOWMAN_WORKFORCE_WORKER_API_ENABLED` defaults false independently of public
intake. Production public relay tasks must keep it false. Only a private
Cloudflare/AWS-addressed service with security-group/edge restrictions may turn
it on; signed service identity remains required even on that private network.
The API foundation does not itself constitute the AWS worker, model gateway,
sandbox, scheduler, or staged execution proof.
