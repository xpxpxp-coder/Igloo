# Snowman private model gateway

Status: service, client contract, dormant AWS task boundary, private ingress
substrate, coordinator-grant enforcement, durable lost-response accounting,
and local tests are implemented; inference deployment and staged proof remain.

The agent path authenticates the coordinator's domain-separated KMS-HMAC model
grant and then requires the exact UUID tenant, job, task, lease generation,
model, specialist role, capability, classification, minimization-evidence
digest, deadline, token ceilings, and cost ceiling. It also compares the
SHA-256 of the presented grant with the digest stored on the live job. A valid
bearer grant is never sufficient by itself.

`snowman-model-gateway` is the only generative model boundary used by governed
Analyst 360 execution. Command Center clients and workforce workers never receive
a provider endpoint or credential and cannot call a model runtime directly.

## Enforced request path

1. Analyst resolves immutable evidence under its own tenant/client/project
   authority and submits only bounded governed artifact projections.
2. Analyst signs the exact canonical request with its asymmetric AWS KMS key.
3. The gateway verifies the exact principal/key binding, freshness and a
   one-time Valkey nonce, then re-evaluates tenant, client, project, specialist
   role, capability, classification, model, token and cost policy.
4. The route comes only from operations configuration. It must be a private
   `.internal`/`.local` HTTP origin, a Snowman-owned HTTPS origin, or an exact
   same-account SageMaker endpoint and inference component; request data can
   never select or override either coordinate.
5. The gateway invokes either a pinned OpenAI-compatible Snowman runtime with
   proxies and redirects disabled or SageMaker Runtime through the VPC interface
   endpoint and task-role SigV4 authentication. It accepts only JSON, enforces a
   hard response-size ceiling, rejects partial model output, validates exact
   usage/cost ceilings, and returns content and request digests.
6. Analyst revalidates every response coordinate and digest, packages the
   result under Analyst artifact authority, runs deterministic QA, and creates a
   human approval. Command Center receives only immutable artifact coordinates.

## One-shot agent authority

An executor-side Snowman proxy presents the model grant only in
`x-snowman-agent-model-grant`. The untrusted ACP child never receives provider
credentials or an endpoint other than the private gateway. Agent requests add
the exact `task_id`, `lease_generation`, and
`minimization_evidence_sha256` coordinates; their tenant, client, and project
must all be the grant's UUID tenant boundary.

Before a model call, the gateway performs two short database transactions:

1. It locks the exact request/job/task/lease authority rows, proves the job is
   `started`, the request and task are live, the lease generation is current,
   the job token is not revoked, and both job and lease deadlines are live. It
   atomically reserves the request's worst-case input, output, and cost against
   both job and parent-request cumulative budgets.
2. Immediately before network dispatch it rechecks the same live authority and
   changes the reservation from `reserved` to `indeterminate`. That committed
   transition is the dispatch linearization point. Cancellation that commits
   first changes the reservation to `aborted` and prevents dispatch;
   cancellation after the transition prevents future generations but cannot
   pretend an already-authorized model call never happened.

No database transaction or row lock is held across provider I/O. A successful
reply atomically replaces the worst-case reservation with actual usage, appends
one `snowman_spend_ledger` receipt, and stores only provider/response digests.
Malformed or over-budget replies are still accounted before their output is
rejected. A crash, timeout, or lost provider/gateway/client response leaves the
worst-case reservation in `reserved` or `indeterminate`, so its possible spend
cannot disappear from the next budget decision.

The UUID `generation_id` is the idempotency coordinate. An exact retry never
invokes the backend again. It receives a `409
generation_reconciliation_required` response containing status, accounted
usage, and any durable provider/response digests. A conflicting request that
reuses the UUID is rejected as a replay.

The gateway stores no prompt or output. Its dedicated PostgreSQL identity can
read only the request/task/lease/job authority rows, insert/update only the
model-generation reservation ledger, and select/append only the spend ledger;
it cannot change live authority, delete evidence, or read collaboration/audit
content. Its dedicated Valkey identity can only
`SET` replay keys under `snowman:model-gateway:nonce:*` and `PING`. The dormant
ECS task runs without a public IP, as non-root, with a read-only root filesystem
and all Linux capabilities dropped. Its task role has only exact `kms:Verify`
and exact ElastiCache connection grants. SageMaker routes add only
`sagemaker:InvokeEndpoint` on their exact configured endpoint and inference
component ARNs; there is no wildcard inference permission.

The AWS root now also defines a default-off cross-account PrivateLink provider.
It uses an internal Network Load Balancer with Snowman TLS, endpoint-service
acceptance, and an exact Analyst-account principal allowlist. PrivateLink
traffic bypasses the NLB's empty client-ingress rule set only at the AWS service
boundary; the NLB security group can egress solely to the model-gateway security
group on port 8443. No public load balancer, public IP, CIDR ingress, peering, or
shared VPC is introduced.

Transient inference failure is now an explicit `503` contract with a bounded
`inference_unavailable` code, `retryable=true`, and `Retry-After: 60`. Analyst
derives one stable generation ID per exact job/model/role/capability tuple and
honors the retry floor, while permanent request, policy, authorization, replay,
and budget failures remain non-retryable. Lost-success response reconciliation
is still a separate production gate.

## Remaining production gates

- Provision and prove the Analyst interface endpoint plus its TLS/DNS identity;
  the provider-side PrivateLink substrate is now defined but remains dormant.
- Build, evaluate, pin, scan, sign, and deploy the Snowman-hosted inference
  images and weights into the now-defined hard-dormant private inference fleet.
  Hosted third-party inference remains prohibited.
- Prove the now-implemented stable generation and retry contract in staged
  scale-from-zero operation without duplicate charges or artifacts.
- Connect the executor-local OpenAI-compatible proxy to the now-enforced agent
  path without exposing the grant to the ACP child, and prove it against a real
  one-shot runtime.
- Run PostgreSQL-backed concurrency tests for request-wide reservations,
  cancellation winning before dispatch, exact replay, lost commit responses,
  and reconciliation. The source/migration contracts are implemented, but the
  repository test environment did not provide a production-equivalent
  PostgreSQL service for this evidence.
- Add saturation, timeout, cancellation, malformed-backend, cross-tenant,
  direct-egress denial, failover, and recovery tests in dormant staging.
- Export immutable route/catalog, image, KMS/IAM, network, test, and cost
  evidence before any desired count can be raised.

These gates prevent a production-readiness claim; they do not require a Block
service or any non-Snowman runtime endpoint.
