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
| `POST /api/snowman/v1/work-requests/{request_id}/cancel` | `workforce.requests.cancel` | Idempotently cancels every non-terminal task, deletes every live lease, and appends human-attributed hash-chain evidence. |
| `POST /api/snowman/v1/work-requests/{request_id}/tasks/{task_id}/approval` | `workforce.tasks.approve` | Records an idempotent approve/deny/revoke decision bound to the exact task snapshot and an expiry of at most 24 hours. |

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
  identity holding both `workforce.plan` and `workforce.tasks.execute`;
- `SNOWMAN_MODEL_GATEWAY_URL` on a Snowman-controlled HTTPS domain; and
- `SNOWMAN_PLANNING_MODEL_ID` from the evaluated model catalog.

The Helm chart keeps intake disabled by default until that identity, gateway,
and an active tenant-local evaluated catalog row exist. AWS workers, scheduler,
sandbox, private worker network deployment and runtime proof, cancellation,
approvals, and staged failure evidence remain open launch gates.

## Private worker control path

Source support now exists for a separately addressed private worker service:

| Route | Behavior |
| --- | --- |
| `POST /internal/snowman/v1/workforce/tasks/claim` | Idempotently leases the next task assigned to the authenticated service identity. |
| `POST /internal/snowman/v1/workforce/tasks/{lead_task_id}/plan` | Rehydrates server-owned request constraints, evaluates a proposed specialist DAG, selects approved models, and atomically replaces the leased lead task. |
| `POST /internal/snowman/v1/workforce/tasks/{task_id}/heartbeat` | Renews only the matching live fencing generation and bearer lease. |
| `POST /internal/snowman/v1/workforce/tasks/{task_id}/spend` | Records an actor-, task-, request-, model-, and provider-receipt-bound ledger entry under hard caps. |
| `POST /internal/snowman/v1/workforce/tasks/{task_id}/finish` | Atomically records a terminal result and hash-chain evidence event under the current lease. |
| `POST /internal/snowman/v1/workforce/requests/{request_id}/context-packets` | Publishes a bounded metadata-only handoff under the writer's current fenced task lease. |
| `GET /internal/snowman/v1/workforce/requests/{request_id}/context-packets` | Lists only non-expired manifests for an actively assigned reader; artifact bodies remain in their authority. |
| `POST /internal/snowman/v1/workforce/requests/{request_id}/proactive-actions` | Evaluates an authorized trigger and, for a non-rejected v2 contract, atomically creates a model-routed ordinary work task under the existing approval/lease/spend/evidence controls. |
| `POST /internal/snowman/v1/workforce/maintenance/tick` | Idempotently enforces deadlines, recovers expired leases, dead-letters exhausted tasks, expires stale proactive proposals, and appends transition evidence. |

Every route requires a live `service` workforce binding and the exact
capability appropriate to the operation. Claim, heartbeat, spend, and finish use
`workforce.tasks.execute`; plan commit uses `workforce.plan` and the same live
lease proof. Task claim also rechecks every task-specific capability and the
active role/classification model route in PostgreSQL. A worker-generated
`claim_id` and a deterministic,
domain-separated relay HMAC make lost claim responses retryable without a
second lease. Lease tokens are stored only as SHA-256 digests. Spend and finish
operations are idempotent and reject stale fencing generations.
Claim replay, heartbeat, spend, and completion also revalidate the live
task-specific grants, service-identity lifecycle, current approval snapshot, and
catalog route; revocation or route suspension cannot be bypassed by retaining an
unexpired lease token.

Maintenance uses a distinct service identity holding only
`workforce.maintenance`. The database stores the exact tick receipt and appends
`request.expired`, `task.expired`, `task.requeued`, `task.dead_lettered`, or
`proactive.expired` in the same transaction as each state transition. The
scheduler cannot claim a task or invoke Analyst/model services.

Human cancellation is a separate public control path. The server derives the
tenant and human actor from the signed request, accepts only a bounded
machine-readable reason code, locks the request, marks every non-terminal task
cancelled, deletes all of its leases, and appends `request.cancelled` evidence in
one transaction. A worker holding a formerly valid lease therefore cannot
heartbeat, record spend, or finish after cancellation commits. Exact
`cancellation_id` retries return the original result; conflicting reuse and
terminal-state cancellation fail closed.

Approval requests never accept free-form rationale or a replacement action.
The command center submits the task's published execution-snapshot digest, a
content digest for the rationale retained by the governed evidence authority,
and an expiry no more than 24 hours after the decision. Approval advances only
the matching gated snapshot. Denial or revocation immediately deletes any live
lease, and every decision appends `task.approval_decided` evidence. Exact
`approval_id` retries are safe; conflicting reuse, stale snapshots, terminal
requests, and terminal tasks fail closed.

The proposal schema never accepts a gateway URL or selected model. It accepts a
bounded role, distinct service identity, requested model override (optional),
capabilities, immutable context references, DAG edges, budgets, risk posture,
and artifact type. The policy kernel rejects cycles, ambient capabilities,
duplicate identities, unsafe irreversible execution, and missing independent
client-ready review. It chooses the best evaluated route allowed for the tenant
and data class. PostgreSQL then independently rechecks the lease, remaining
request budget, active service identities and grants, catalog status, route,
role, classification, and DAG before one atomic commit. Exact retries return the
original plan; conflicting retries fail closed.

`SNOWMAN_WORKFORCE_WORKER_API_ENABLED` defaults false independently of public
intake. Production public relay tasks must keep it false. Only a private
Cloudflare/AWS-addressed service with security-group/edge restrictions may turn
it on; signed service identity remains required even on that private network.
Proactive auto-run is fail-closed by default: its capability allowlist is empty,
its automatic cost ceiling is zero, and its minimum confidence is 10,000 basis
points. A private scheduler deployment may explicitly set
`SNOWMAN_PROACTIVE_AUTOMATIC_CAPABILITIES`,
`SNOWMAN_PROACTIVE_MAX_AUTOMATIC_COST_MICROUSD`, and
`SNOWMAN_PROACTIVE_MINIMUM_CONFIDENCE_BASIS_POINTS`; the relay records the exact
policy digest used for every decision.
The v2 proposal also requires a distinct executor identity, supported
role/capability pair, content-addressed instruction, bounded context, evaluated
model proposal, token/cost ceilings, artifact type, schedule, expiry, and retry
cap. The server selects the model, binds the complete execution snapshot, and
materializes only automatic or approval-gated decisions as ordinary work tasks.
Rejected actions create no executable task. Database triggers keep the proactive
status synchronized with task claim, approval, completion, cancellation,
expiry, requeue, and dead-letter transitions. The v2 decision receipt returns
the task, executor, selected model, execution-snapshot digest, and approval flag
under `execution`; it is `null` for a rejected action.
The identity-isolated worker and maintenance scheduler now implement claim,
planning, heartbeat, governed Analyst dispatch/status, context publication,
terminal completion, deadline enforcement, lease recovery, and dead-lettering
in source. Capability-specific Analyst job executors, proactive action
execution, sandbox boundaries, AWS activation, and staged execution/recovery
proof remain open.

## Analyst lifecycle events

The separate, private `POST /internal/snowman/v1/analyst-events` route accepts
only strict, minimized Analyst 360 job lifecycle events. It is not a general
webhook and does not accept raw query results, transcripts, client rows,
credentials, prompts, or arbitrary destination coordinates. Each event must be
bound to the host-derived community's exact tenant/client/project identifiers
and an active Analyst service/KMS key registration.

`SNOWMAN_ANALYST_EVENT_API_ENABLED` defaults false and requires governed
workforce identity. The receiver verifies a fresh, one-time asymmetric AWS KMS
assertion over the exact HTTP method, route, canonical body digest, principal,
key, timestamp, nonce, and `events.ingest` operation. It then persists the event
idempotently and returns an independently KMS-signed, digest-bound delivery
receipt. The endpoint belongs on a separately addressed private integration
service, not the public relay task.
