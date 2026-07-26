# Snowman Command Center production acceptance criteria

Production activation is prohibited until every required gate is linked to
immutable evidence from the release candidate. A passing unit test alone is not
evidence for a runtime, recovery, accessibility, or operational claim.

## P0 launch gates

### Architecture and data boundary

- Command Center and Analyst 360 use separate Postgres, Redis/Valkey, S3, KMS,
  secret, task-role, network, backup, and telemetry resources.
- A checked, versioned integration schema allowlists every field crossing the
  boundary and rejects unknown fields.
- Contract and runtime tests prove raw Aptive rows, extracts, transcripts,
  credentials, and unbounded query results cannot cross the default integration.
- Content-addressed artifact references are verified before use and preserve
  classification, tenant, retention, and evidence authority.

### Snowman-only network authority

- Production configuration contains no Block-operated relay, registry, update,
  push, pairing, media, download, telemetry, git, image, or chart endpoint.
- DNS and runtime egress tests prove the application can reach only explicitly
  allowlisted Snowman-controlled services and approved external connectors.
- Containers and deployment charts require a Snowman-owned digest; no mutable
  `main`/`latest` or upstream registry default can start production.
- OTLP, product analytics, crash reporting, update checks, and support uploads
  are disabled unless their exact Snowman-controlled destination is configured.
- Every approved external processor appears in the dependency register with
  data classes, purpose, tenant scope, retention, credentials, disable switch,
  evidence, and accountable acceptance.
- A negative integration test captures DNS/HTTP/WebSocket attempts and fails on
  any unregistered destination, including redirects and dynamically resolved IPs.

### Human identity and authorization

- Production accepts Snowman workforce OIDC; issuer, audience, signature,
  nonce/state/PKCE, authentication time, and tenant binding fail closed.
- A human-to-Nostr binding is explicit, tenant-scoped, auditable, revocable, and
  protected against reassignment.
- Google provider tokens, email addresses, raw provider subjects, Analyst
  cookies, and client data never cross the human-enrollment boundary; deployed
  network capture, database inspection, and audit reconciliation prove it.
- The identity assertion key is asymmetric, purpose-dedicated, and cross-account:
  Analyst can sign but not administer Command Center identity state, while the
  exact Command Center relay role can verify but cannot sign.
- Roles map to named capabilities; no production path maps key possession to all
  known scopes.
- Session duration, idle expiry, device/session inventory, logout, global
  revocation, workforce removal, and key rotation pass end-to-end tests.
- Sole-founder administration is supported without fabricated multi-person
  ceremonies. An independent reviewer is required only where the control or
  assurance claim explicitly requires independence.

### Agent identity and tool safety

- Each agent/runtime/workspace has a unique tenant-bound service identity,
  short-lived credential, owner, capability set, and revocation path.
- `buzz-dev-mcp` shell/file mutation is disabled by default in production.
- Any enabled execution runs inside a proven sandbox with scoped mounts,
  resource/time limits, process isolation, deny-by-default egress, no ambient AWS
  credentials, brokered secrets, and a complete command/tool receipt.
- High-impact file, network, deployment, identity, secret, billing, data export,
  and destructive operations require an expiring, identity-bound approval.
- Prompt injection, confused-deputy, capability escalation, secret exfiltration,
  path traversal, symlink, process-tree escape, and network bypass tests pass.

### AI workforce orchestration and model governance

- A request is decomposed into an auditable work plan and routed to explicitly
  scoped specialist roles; every role has a selected model, capability grant,
  tenant/workspace identity, budget, deadline, inputs, expected artifacts, and
  quality criteria.
- Model selection optimizes quality, latency, and cost only among routes allowed
  for the tenant and data class. Desktop and workers call a Snowman-controlled
  gateway; direct model-vendor credentials and endpoints never reach agents.
- Every enabled self-hosted model has a digest-pinned Snowman image, verified
  content-addressed weights, usage/provenance record, role-specific quality and
  safety evaluation, private endpoint/component binding, bounded capacity, cost
  alarm, rollback, and kill-switch evidence.
- Scale-from-zero tests prove the expected first-call capacity failure is retried
  under the same fenced generation and spend reservation until its deadline,
  without duplicate charges, artifacts, approvals, or lifecycle completion.
- A durable AWS queue, scheduler, lease/heartbeat protocol, idempotent execution,
  retries, cancellation, dead-letter handling, concurrency/rate limits, and
  runaway spend controls prove that work continues safely without a desktop
  session and recovers after worker or dependency failure.
- Context packets are bounded, classified, versioned, content-addressed, and
  evidence-linked. New or replacement agents can reconstruct task state without
  receiving raw Aptive rows, unbounded transcripts, credentials, or another
  tenant's memory.
- Agent handoffs, delegation, disagreement, synthesis, independent quality/risk
  review, artifact publication, and human-gated exceptions create correlated
  receipts and are covered by deterministic and model-evaluated test cases.
- Proactive actions arise only from an authorized objective, schedule, signal,
  or policy. The system records why the action is useful, confidence, deadline,
  cost/risk tier, execution decision, outcome, and next review time.
- Notifications, reminders, analytics refreshes, deadline monitoring, and safe
  reversible next steps run 24/7 in staging; external, destructive, privileged,
  or high-impact actions stop at an expiring human approval.
- Work products pass tenant-specific factuality, evidence, completeness,
  accessibility, presentation, and client-readiness checks before delivery.

### Workflow safety

- Every supported action has runtime implementation, authorization, idempotency,
  timeout, retry, cancellation, redaction, and audit tests.
- Unsupported actions fail workflow definition validation before activation.
- Approval requests bind tenant, workflow/run/step, canonical action digest,
  requester, required approver capability, expiry, and one-time decision.
- Resumption revalidates policy and action digest; stale or altered requests fail.
- Webhooks enforce HTTPS, allowlisted destinations, DNS/IP revalidation, private
  address denial, bounded payloads/responses, brokered credentials, and evidence.

### Tenant isolation

- Adversarial two-tenant tests cover WebSocket AUTH/EVENT/REQ/COUNT, HTTP bridge,
  channels, DMs, feeds, profiles, search, media, git, workflows, approvals,
  audit, presence, pub/sub, caches, rate limits, operator APIs, logs, metrics, and
  the Analyst 360 adapter.
- Direct and proxied requests prove unknown, malformed, ambiguous, forwarded, and
  spoofed hosts fail closed under the deployed ALB/proxy configuration.
- The Aptive workspace has explicit data classification and retention policy and
  no test uses production client data.

### Audit and evidence

- Application audit chains remain tenant-separated and verify continuously.
- Periodic chain checkpoints are signed with a dedicated KMS key and written to
  immutable, versioned retention outside the application database.
- Deletion/rewriting/rechaining by a simulated database writer is detected by
  external checkpoint verification.
- Every governed command has correlated request, authorization, approval when
  required, execution, result, evidence manifest, and observer receipts.
- Clock, canonicalization, retry, duplicate, and partial-failure behavior pass.

### Supply chain and release

- Release source is a reviewed Snowman commit/tag; build actions and dependencies
  are pinned and policy-scanned.
- Relay, web, desktop, mobile, CLI, and deployment artifacts have inventories,
  SBOMs, vulnerability results, provenance, signatures, and retained digests.
- AWS deploys accept only approved digest-pinned Snowman images and verify trust.
- Applicable upstream license notices and provenance ship with every artifact.
- Update endpoints, bundle IDs, package metadata, deep links, registry names,
  docs, and release channels are Snowman-controlled or deliberately retained for
  documented compatibility.

### AWS staging and operations

- Terraform plan proves managed PostgreSQL, managed Redis/Valkey, S3/KMS,
  ALB/WAF, ACM/Route53, Secrets Manager, least-privilege ECS/Fargate roles,
  private networking, logs, metrics, alarms, backups/PITR, and cost controls.
- The staging release is deployed by immutable digest and remains dormant or
  scaled down when not under verification.
- Health, readiness, dependency degradation, autoscaling, rolling deployment,
  rollback, secret rotation, and regional dependency failure exercises pass.
- SLOs, dashboards, synthetic probes, paging destinations, runbooks, ownership,
  and evidence retention are verified for a sole-founder operating model.
- Budget thresholds, cost-allocation tags, log/object retention, storage quotas,
  and runaway agent/workflow controls are active and tested.

### Backup and recovery

- PostgreSQL PITR, Redis/Valkey recovery expectations, S3 version recovery, KMS
  dependency, secrets, configuration, and infrastructure rebuild procedures are
  documented and tested from clean recovery targets.
- Restore evidence records RPO/RTO results, integrity checks, tenant isolation,
  application smoke tests, and cleanup.
- Restore testing never overwrites the only usable copy of staging or production
  evidence.

### Product quality, accessibility, and performance

- Central Snowman product identity and design tokens cover desktop, web, mobile,
  CLI, deployment, documentation, operational alerts/dashboards, legal/about,
  installers, and update surfaces.
- No user-visible Buzz/Sprout/Block/bee/hive identity remains unless listed in a
  compatibility exception inventory.
- Keyboard-only, focus order/visibility, zoom/text scaling, contrast, reduced
  motion, screen-reader semantics, error/status announcements, touch targets,
  and mobile platform accessibility pass automated and manual checks.
- Critical journeys meet recorded latency, reconnect, CPU/memory, bundle/startup,
  and concurrent-agent targets under realistic staging load.

### UAT and activation

- UAT covers workforce sign-in/revocation, Aptive tenant entry, governed Analyst
  360 request, status observation, evidence/citation resolution, recommendation,
  approval/denial, decision/outcome capture, agent failure/cancellation, tenant
  switching, and recovery/rollback.
- The launch bundle contains exact commit/image/artifact digests, test reports,
  IaC plans/applies, security scans, accessibility results, backup restore proof,
  dashboards/alarms, cost estimate, known-risk decisions, and rollback steps.
- Production traffic remains disabled until the sole-founder operator records
  final activation acceptance after reviewing the immutable launch bundle.

## Irreducible user-owned dependencies

Only actions that require control of an external identity or an explicit business
risk decision remain user-owned. Expected examples are inbox confirmation of a
monitored alert subscription, control of workforce/registrar/payment accounts,
external app-store signing acceptance, an independent report where required,
and final production activation. Technical configuration, validation, evidence
capture, and exact instructions must be completed before any such dependency is
presented.
