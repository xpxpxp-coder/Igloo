# Snowman one-shot agent executor boundary

Status: source infrastructure foundation; runtime and staging proof incomplete.

## Product role

Igloo's ACP harness is the runtime-neutral execution interface for Snowman's
specialist team. OpenClaw, Hermes, Codex, Claude, Goose, or another framework
may be packaged behind that interface only as an evaluated runtime adapter.
None is required to own orchestration, memory, identity, authorization, model
routing, connectors, or audit state.

The durable workforce service remains the trusted scheduler and lease
coordinator. Open-ended work runs in a separate one-shot ECS/Fargate task. A
runtime that can plan broadly and use tools is useful precisely because its
authority is narrower than its reasoning capability.

## Execution sequence

1. The trusted coordinator fences an exact tenant, workspace, request, task,
   generation, runtime, model policy, cost ceiling, deadline, input manifest,
   expected artifacts, and capability set.
2. The broker creates an opaque, one-job credential bound to that snapshot.
   The credential is not a relay key, human session, AWS credential, model
   provider key, or general connector token.
3. The coordinator starts the digest-pinned runtime task. No ECS service is
   created and the task definition deliberately has no `task_role_arn`, so the
   untrusted process receives no AWS task credentials.
4. The executor retrieves only the bounded context packet authorized by the
   broker. Raw Aptive rows, extracts, transcripts, identifiers, credentials,
   and unbounded query results remain in Analyst 360.
5. Model calls go only through the private Snowman model gateway. Tool and
   external-action requests go only to the purpose-specific broker, which
   rechecks the active lease, capability, approval, destination, cost, and
   canonical action digest on every call.
6. The broker preserves redacted command/tool receipts and content-addressed
   result/artifact evidence. A separate quality/risk agent reviews client-ready
   work before delivery when policy requires it.
7. Completion or cancellation revokes the job credential, stops the task, and
   destroys its bounded scratch volumes. Retry uses a new generation and
   cannot reuse the previous credential or completion receipt.

## Network and process boundary now defined in source

`infra/aws/agent_executor.tf` creates only dormant, one-shot task definitions
for reviewed runtime profiles. Each profile requires a Snowman ECR digest plus
SBOM, provenance, and evaluation evidence digests. The task runs non-root with
a read-only root filesystem, dropped Linux capabilities, bounded CPU, memory,
duration and ephemeral storage, and two explicit writable mounts. It has an
ECS execution role for the exact image and redacted log group only; that role is
used by the ECS agent and is not exposed as a task role.

`infra/aws/network.tf` gives the task no NAT, public address, public default
route, direct relay route, Analyst route, object-store route, or connector
route. Its security group can resolve VPC DNS and reach only:

- a distinct private Snowman agent-broker security group;
- the private Snowman model-gateway security group; and
- ECR API/ECR Docker/CloudWatch Logs interface endpoints carrying a separate
  endpoint security group.

The shared KMS, Secrets Manager, STS, SSM, SageMaker, and other application
endpoint security group is not reachable from the agent task. Direct provider
endpoints and Block-operated services are absent.

## Incoming data is not authority

Trusted source authentication answers who supplied bytes; it does not make
those bytes safe instructions. Email, documents, webpages, files, calendar
events, repository content, and connector payloads can contain prompt
injection, malicious attachments, false claims, tracking URLs, oversized
content, or instructions to exfiltrate secrets. Every inbound item is therefore
classified as untrusted content and may inform a task, but cannot grant a tool,
change policy, choose an unapproved destination, reveal memory, select a higher
data class, install a plugin, or approve its own action.

PII is one protected class, not the whole risk boundary. Confidential strategy,
client work product, contractual data, credentials, system prompts, model
responses, logs, artifact drafts, and cross-tenant metadata also require the
same minimization and no-egress enforcement.

## Remaining activation gates

The `snowman-agent-executor` binary now implements the credentialless one-shot
client side of this contract: exact Snowman origins, proxy/redirect denial,
bounded digest-verified snapshot retrieval, runtime/model/job/generation and
deadline checks, immutable image-manifest checks, fail-closed ACP model
selection, adapter-local permission rejection, bounded final-answer capture,
and idempotent start/result receipts. It accepts no relay key, AWS task
credential, direct provider credential, or arbitrary executable/MCP path.

The matching private job broker, shared versioned contracts, durable job
ledger, and lease-backed idempotent issuance function now exist in source. The
broker returns only digest-bound snapshots and accepts only bounded exact start
and result receipts under a one-job token. It is a separate private service,
not a relay or Block endpoint.

This is not yet an executable production sandbox because deployment,
coordination, tools, and model authorization remain dormant. Activation still
requires:

- separately pinned adapter images (including any evaluated OpenClaw or Hermes
  adapter) that package the executor and exact immutable runtime manifest;
- the broker/coordinator database roles and secrets, private service/listener,
  cancellation/expiration/purge, capability-specific action receipts, and
  approval enforcement;
- coordinator `RunTask`/`StopTask` logic with exact task-definition and
  `iam:PassRole` restrictions outside the untrusted task;
- a broker-authenticated model-gateway path for agent principals;
- a short-lived model-gateway credential that is distinct from the job token
  and cannot reach a direct model provider;
- sandbox cancellation, timeout, process-tree, scratch-destruction, log
  redaction, prompt-injection, credential-exfiltration, DNS, redirect, and
  destination-denial tests; and
- immutable image verification plus live dormant-to-active-to-dormant staging
  evidence and cost measurement.

Until those pass, desktop ACP is development-only and AWS agent profiles remain
dormant infrastructure definitions.
