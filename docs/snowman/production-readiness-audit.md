# Snowman Command Center source-level maturity audit

Status date: 2026-07-25  
Audited baseline: `c2a4ee711e481bb427d6cf8cd08b2c7329d1508c`  
Fork relation at baseline: `origin/main` and `upstream/main` identical

## Outcome

Igloo/Buzz materially improves the delivery speed, capability, usefulness, and
visible quality of Snowman 360. It supplies a mature collaboration and agent
operations substrate that would be expensive to rebuild: a Rust relay, signed
realtime events, desktop/web/mobile clients, CLI, channels and direct messages,
threads, media, search, git hosting, agent observation, workflows, Postgres,
Redis fan-out, S3-compatible storage, telemetry, and a per-community audit
chain.

The correct decision is **adopt with hardening as a separate command center**,
not merge its data stores into Analyst 360 and not ship the upstream baseline.
The highest-risk gaps are identity/authorization, agent tool containment,
approval coverage, externally anchored audit integrity, deployment/recovery
evidence, and systematic Snowman branding.

## Source-backed maturity matrix

| Area | State | Source evidence | Snowman decision |
| --- | --- | --- | --- |
| Signed realtime protocol and relay | Proven | `crates/buzz-core/src/kind.rs`; `crates/buzz-relay/src/handlers/{auth,event,req}.rs` | Preserve Nostr wire kinds and signatures beneath the Snowman identity layer. |
| Collaboration surfaces | Proven | `desktop/src/features`; `web/src/features`; `mobile/lib/features`; `crates/buzz-cli/src` | Reuse as command-center experience; verify each critical journey during UAT. |
| Host-derived community boundary | Proven in substantial implementation and conformance coverage | `crates/buzz-relay/src/tenant.rs`; `crates/buzz-test-client/tests/conformance_multitenant.rs`; community-scoped DB modules | Keep. Add trusted-proxy/host-header threat tests and Snowman integration tests before launch. |
| Human authentication | Hardening required | `crates/buzz-auth/src/lib.rs` explicitly has no JWT/IdP dependency; NIP-42 possession is the human identity proof | Add workforce OIDC binding, short sessions, device/session inventory, lifecycle, and revocation. |
| Human authorization | Hardening required | `AuthService::verify_auth_event` grants `Scope::all_known()`; `scope.rs` includes admin scopes | Replace possession-implies-all with tenant-scoped Snowman roles and capabilities. Membership remains a resource boundary, not the whole authorization model. |
| Agent identity | Hardening required | `desktop/src-tauri/src/managed_agents/runtime.rs` injects an agent Nostr private key and owner metadata | Issue a distinct service identity per agent/runtime/workspace; bind it to tenant, owner, capabilities, TTL, and revocation state. |
| Agent shell/file tools | Hardening required, high risk | `crates/buzz-dev-mcp/src/shell.rs` accepts an arbitrary command and selects a host shell, but shell is now default-off/workspace-contained and the ACP/MCP child boundary removes relay, cloud, and provider credentials | Keep disabled by default. Require the external Snowman AWS sandbox, brokered signed actions, scoped filesystem, constrained egress, approvals, and complete audit before production use. |
| Workflow engine | Partially proven | `crates/buzz-workflow/src/{schema,executor}.rs`; transactional command handling in `crates/buzz-relay/src/handlers/command_executor.rs` | Retain only after risk classification and approval policy are enforced end to end. |
| Workflow approvals | Hardening required | Approval records/grant/deny/resume exist in `command_executor.rs`; approver syntax currently supports `any` or one pubkey, while role-like specs are rejected | Bind approvers to Snowman identity and capability policy; prevent self-approval where independence is required; expire and audit all decisions. |
| Workflow action completeness | Vision only for named actions | `executor.rs` returns `NotImplemented` for `SendDm` and `SetChannelTopic` | Do not advertise or accept these actions until implemented and tested, or reject them at definition validation. |
| Outbound workflow calls | Hardening required | `ActionDef::CallWebhook` and executor/sink implement external HTTP behavior | Apply destination allowlists, DNS/IP revalidation, time/size limits, credential references, redaction, approval tiers, and evidence capture. |
| Rate limiting | Proven implementation, production tuning required | `crates/buzz-auth/src/rate_limit.rs`; relay configuration and Redis-backed limiter wiring | Treat older contrary prose as stale; load/adversarial test tenant fairness and failure behavior. |
| Audit chain | Proven tamper-evidence, insufficient tamper resistance | `crates/buzz-audit/src/{hash,service}.rs` uses unkeyed SHA-256 and DB-resident chain rows | Add KMS-signed periodic checkpoints and immutable external retention. A DB writer can currently rewrite rows and recompute the chain. |
| Multi-node fan-out | Proven implementation plus IAM refresh path; operational proof pending | `crates/buzz-pubsub`; `crates/snowman-aws-auth`; relay Redis subscriber/fan-out paths | Test IAM refresh, failover, reconnect/resubscription, duplicate suppression, and degraded Valkey behavior in staging. |
| Storage/search/media tenant scoping | Substantially proven, adversarial proof pending | community-aware modules in `crates/buzz-db`, `buzz-search`, `buzz-media`; multitenant conformance tests | Add cross-tenant signed-event, REST, media, search, git, workflow, pub/sub, and cache tests to the launch gate. |
| Observability | Useful baseline | `crates/buzz-relay/src/{metrics,telemetry}.rs`; chart metrics/health configuration | Standardize Snowman OTLP, structured audit-safe logs, SLOs, dashboards, paging, synthetic probes, and runbooks. |
| Supply chain | Useful baseline | pinned GitHub Actions; Docker provenance attestation in `.github/workflows/docker.yml`; multi-platform release workflows | Add Snowman-owned registries/signing trust, SBOM and vulnerability policy, dependency review, reproducible release evidence, and digest-only deploys. |
| Deployment | Validated managed AWS substrate and default-off authenticated edge; live compute/recovery proof incomplete | `infra/aws`; Compose remains unsuitable for production | Keep Compose out of production. Prove the mTLS ALB/WAF edge and least-privilege ECS tasks in staging; complete image trust, backup vault/recovery, live plan, and staged proof. |
| Accessibility | Meaningful component-level work, acceptance proof absent | extensive ARIA/reduced-motion usage and UI tests across desktop/web/mobile | Add automated axe/semantic checks plus keyboard, zoom, contrast, screen-reader, and mobile accessibility UAT evidence. |
| Branding | Hardening in progress | `product/{identity,design-tokens}.json`, `scripts/generate-snowman-product.mjs`, generated desktop/web/admin/mobile identities and tokens, Snowman icons, and `scripts/check-snowman-brand.mjs` now establish one checked product authority | Complete the legacy-copy sweep across secondary screens, deployment/store metadata, CLI help, and operations docs; preserve only registered wire/process compatibility names and obtain accessible visual UAT evidence. |
| Analyst 360 integration | Bidirectional client/receiver and durable workforce worker implemented in source; Analyst executors and runtime proof required | `crates/snowman-analyst-client`; `crates/snowman-workforce-worker`; `crates/buzz-relay/src/api/analyst_integration.rs`; `crates/buzz-db/src/analyst_integration.rs`; `migrations/0029_snowman_analyst_event_boundary.sql`; Analyst 360 migration 047, command/outbox modules, and dedicated delivery worker | Keep the asymmetric, versioned command/event boundary. Build capability-specific Analyst job executors with model/cost revalidation; complete private AWS routing, KMS/IAM provisioning/bindings, and adversarial cross-tenant staging proof; never share databases or copy raw Aptive rows/transcripts here by default. |

## Hardening progress after the audited baseline

The working branch now includes source-level foundations that materially reduce
the highest risks without changing the production-readiness verdict:

- governed relay role scopes plus active workforce human-session or
  capability-bounded service-identity resolution;
- serialized, receipt-preserving human enrollment retries that recover from a
  lost HTTP response without creating a second session, while rejecting any
  assertion reuse whose authority, body, identity, device, or proof differs;
- a Snowman desktop enrollment protocol that signs the exact assertion,
  broker, community, purpose, nonce, human verification code, Snowman origin,
  expiry, protocol, and version; external origins and cross-origin callbacks
  fail before device signing;
- tenant-scoped durable work requests/tasks, model-per-specialist routes,
  fenced leases, retry/dead-letter recovery, exact-snapshot approvals, immutable
  context references, and hard token/cost ledgers;
- a versioned human request/status API that derives tenant and actor authority
  server-side, requires exact workforce capabilities, creates only a bounded
  planning task, and exposes metadata-only hash-chain evidence;
- independently disabled private service-identity routes for idempotent claim,
  fenced heartbeat, governed lead-to-specialist DAG/model expansion,
  lease-bound spend, and atomic terminal evidence; and
- Snowman-only model, update, release, pairing, push, image, and workflow
  destination enforcement with an automated production-boundary scanner;
- default-off agent shell/network access, workspace containment, ambient secret
  removal, and direct provider endpoint rejection; and
- ACP agent children no longer inherit relay signing/owner credentials, cloud
  or direct model-provider secrets; MCP receives only the relay address, and
  Codex tool network access is forced off after persona/parent config merging;
- dormant one-shot Fargate agent task definitions now require digest-pinned
  Snowman runtime images plus SBOM/provenance/evaluation evidence, omit the ECS
  task role entirely, expose only bounded scratch mounts, and use a dedicated
  security group that can reach only the future private broker, model gateway,
  VPC DNS, and isolated ECR/log endpoints; no agent service is created;
- the matching relay-independent executor now validates a digest-verified,
  tenant/job/generation/runtime/model/deadline-bound snapshot, rejects local
  adapter permission escalation, captures only bounded final-answer text, and
  returns idempotent start/result receipts without receiving a relay or AWS
  task credential;
- a separate private broker and durable one-shot job ledger now bind an opaque
  token to one active tenant/task/generation/runtime/model snapshot, enforce
  constant-time authentication and exact idempotent receipts, and explicitly
  deny the general relay database role access to job authority;
- the governed one-shot bootstrap now creates and verifies the broker's exact
  read/update-only database role and writes only its TLS RDS URL to a separate
  KMS-encrypted secret that the relay execution role cannot read;
- the broker is now packaged in the digest-pinned Snowman image and has a
  hard-dormant private ECS service definition behind an executor-only TLS NLB
  and split-horizon Snowman DNS; it receives no AWS task role or public IP and
  can reach only RDS, VPC DNS, and exact private AWS execution endpoints;
- definition-time rejection of unimplemented workflow actions and unsafe
  webhook destinations/credential headers; and
- a default-off Analyst lifecycle-event ingress with host-derived community
  scope, strict minimized schema, exact asymmetric KMS assertions, replay
  prevention, idempotent persistence, and independently KMS-signed receipts.
- a validated AWS managed-substrate root with no NAT/private internet default
  route, Cloudflare-source-only edge ingress, exact private AWS endpoints,
  managed PostgreSQL/IAM-authenticated Valkey, object lock, KMS, encrypted logs,
  alarms, and budgets; plus a tested streaming SigV4 provider, automatic Valkey
  reauthentication/resubscription, password-free runtime contract, and a
  key/channel/command-bounded Valkey IAM user. It remains unapplied.
- a hard-zero, digest-pinned dormant relay task and ECS service with non-root,
  read-only execution, dropped capabilities, exact task/execution roles, an
  empty governed runtime-secret shell, and layered zero-count preconditions;
- hard-dormant per-identity workers plus maintenance-only, recurring-trigger,
  and fixed-content reminder services with empty AWS task roles, private
  TLS/split-horizon relay routes, deadline and lease recovery, dead-lettering,
  idempotent receipts, and hash-chain evidence;
- a one-shot, no-service database/key bootstrap task that reads only the
  RDS-managed master secret, runs migrations, provisions and verifies a
  DML-only serving identity, generates relay/HMAC keys outside Terraform, and
  now generates/preserves per-service workforce keys only in exact secret
  containers, reconciles fixed role grants and evaluated model routes, records
  a secret-free manifest receipt, and
  writes only the exact KMS-encrypted runtime secret. Relay startup no longer
  performs partition DDL in the AWS contract.

These are implementation foundations, not staged proof. OIDC assertion exchange,
private integration routing, live database/bootstrap evidence, recurring
partition rotation and authenticated-edge bypass tests,
proactive execution, applied broker staging/action tools/model-token path, adapter images, and live sandbox proof,
KMS audit checkpoints, staged
recovery/load/isolation exercises, comprehensive branding, accessibility, UAT,
and launch evidence remain open gates.

## Data classification and boundary

The command center may store coordination metadata, Snowman identity bindings,
tenant-scoped conversations explicitly approved for the control plane, job and
workflow state, redacted summaries, citations, decisions, and immutable artifact
references. It must not become the authority for governed queries, evidence,
memory, recommendations, decisions/outcomes, or client datasets.

For Aptive, the deny-by-default rule is stronger: raw source rows, extracts,
transcripts, query results containing client data, and credentials remain inside
Analyst 360-governed stores. Any exception requires an explicit data-flow review,
field-level minimization, retention decision, and user approval.

## Threat priorities

1. A stolen Nostr key becoming an administrator because cryptographic possession
   currently receives all known scopes.
2. An agent or prompt-injected tool invoking arbitrary shell commands with relay
   credentials and host filesystem/network reach.
3. Cross-tenant leakage through host/proxy ambiguity, caches, pub/sub, media,
   search, git, workflows, logs, or integration events.
4. A database-level attacker rewriting audit history and recomputing its unkeyed
   chain.
5. A workflow causing an irreversible external action without the required
   identity-bound approval and idempotency evidence.
6. Mutable/untrusted artifacts or upstream branding/update channels entering a
   Snowman release.
7. Loss of state or evidence without a tested point-in-time and object-version
   recovery path.

## Audit limits

This is a source-level decision record, not launch evidence. It does not claim
runtime proof for staging failover, backup restoration, cross-tenant adversarial
tests, accessibility, performance, SLOs, or UAT. Those remain explicit acceptance
gates in `production-acceptance-criteria.md`.
