# Snowman agent launch coordinator

Status: private service, least-privilege database bootstrap, crash-fenced launch,
source-IP-attested credential bootstrap, running/expired task reconciliation,
and hard-dormant AWS service definition implemented in source; worker wiring,
model-proxy enforcement, action brokers, and staged proof remain.

## Purpose

The trusted coordinator is the narrow bridge between a governed Snowman
workforce lease and one untrusted, credentialless specialist runtime. It is not
an agent, planner, memory store, relay, connector, model gateway, or Analyst data
service. Native ACP, OpenClaw, Hermes, or another runtime can be selected only
through a reviewed, revision-pinned runtime profile; the coordinator grants none
of them ambient authority.

`POST /v1/tenants/{tenant_id}/launches` accepts only an exact `JobSnapshot` body
with a NIP-98 signature bound to the method, private Snowman URL, and payload
digest. A cryptographically valid signer is still rejected unless its active,
unrevoked service-runtime key is assigned to the exact tenant/request/task.
Exact lost-response retries are idempotent when they carry a fresh signature;
reusing a NIP-98 event is rejected even when the bytes match.

The snapshot contract prohibits PII and requires a SHA-256 minimization/redaction
evidence reference. Raw Analyst datasets, rows, extracts, transcripts, provider
credentials, AWS credentials, relay keys, and direct provider endpoints are not
accepted. Authenticated inbound content remains untrusted data and cannot grant
capabilities, select a destination, or approve an action.

## Crash and credential boundary

- Job and launch evidence commit atomically in PostgreSQL.
- The coordinator stores only the SHA-256 digest of the job credential.
- KMS HMAC-SHA256 deterministically derives the same secret from tenant, job,
  task, generation, and deadline after a crash; the KMS key never leaves AWS.
- A separate deterministic ECS client token binds the exact cluster, pinned task
  definition, container, subnets, and security group. It is not a credential.
- `RunTask` starts exactly one Fargate task, disables ECS Exec and public IPs,
  supplies no task/execution role override, and permits only tenant ID, job ID,
  and deterministic launch ID container overrides. These are public coordinates;
  no bearer credential is placed in the CloudTrail-recorded request.
- The task redeems credentials over the private TLS NLB. The NLB preserves the
  task's IPv4 source; the coordinator matches it to the exact live ECS awsvpc
  attachment, rechecks tenant/job/task/generation, active lease, request/task
  state, deadline, revocation, and both stored token digests, then records the
  source and a maximum-five retry count. Forwarded-IP headers are rejected.
- Launch exhaustion and deadline expiry revoke the broker token. Deadline
  recovery revokes before replaying the idempotent ECS call to recover and stop
  any task whose ARN was lost during a crash.
- Governed cancellation revokes database authority before `StopTask`.
- The service continuously rechecks the exact lease generation, task/request
  state, deadline, and token revocation. It stops lost-authority tasks and
  records terminal ECS/broker state without retaining container diagnostics.

The broker token cannot authenticate to the model gateway. The coordinator now
mints a separate KMS-HMAC model grant binding the exact tenant, job, task fence,
model, specialist role, capabilities, minimization evidence, aggregate budgets,
and deadline; only its SHA-256 digest is stored. The separate broker and model
credentials are delivered only through the source-attested bootstrap response,
never through ECS metadata or an ACP child environment. The executor-local model
proxy and gateway live job-state/spend checks remain mandatory before the model
grant can authorize inference.

## AWS boundary

`infra/aws/agent_coordinator.tf` defines a protected internal TLS NLB and
split-horizon Snowman DNS, a non-root/read-only ECS service, a dedicated
database secret, and a separate task role. Network policy allows only RDS, VPC
DNS, and shared private AWS endpoints. The task role can call `kms:GenerateMac`
on one HMAC key, `ecs:RunTask` on exact reviewed task-definition revisions,
`DescribeTasks`/`StopTask` in the exact cluster, and `iam:PassRole` for only the
corresponding execution roles to `ecs-tasks.amazonaws.com`.

The coordinator accepts only `sslmode=verify-full` PostgreSQL URLs for exact
RDS host and certificate verification.

The coordinator has no public IP, NAT route, Block endpoint, relay route,
Analyst route, model route, object-store route, connector route, or arbitrary
IAM authority. Its desired count is hard-zero in Terraform.

## Remaining activation gates

- Route eligible workforce leases through the launch API and preserve exact
  coordinator receipts in the workforce event chain.
- Wire terminal broker receipts into workforce completion, then complete
  purge/retention and externally checkpointed evidence.
- Complete the executor-local model proxy plus gateway live job-state,
  cancellation, aggregate-spend, and lost-response checks; never reuse the
  broker token. Implement capability-specific action brokers separately.
- Run Postgres integration, NIP-98 replay, cross-tenant, cancellation, crash,
  expiration, source-IP spoofing/reuse, bootstrap lost-response, prompt-injection,
  exfiltration, DNS/egress, and cost tests in AWS.
- Apply an exact reviewed Terraform plan only after workload identity and cost
  posture are reverified. Keep the service at zero outside a test window.

Snowman 360 is not production-ready until those gates and UAT pass.
