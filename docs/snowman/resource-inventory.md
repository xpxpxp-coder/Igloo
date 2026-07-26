# Available resource and reuse inventory

This inventory prevents the production program from rebuilding proven Snowman
assets or accidentally depending on an unapproved upstream service. Runtime
claims require live verification before use.

## Repositories and reusable capabilities

| Resource | Verified state | Reuse decision |
| --- | --- | --- |
| Igloo fork | `main` at `c2a4ee711e481bb427d6cf8cd08b2c7329d1508c`, identical to upstream at audit | Build Snowman Command Center on `codex/snowman-command-center`; preserve compatible Nostr kinds and mature relay/client capabilities. |
| Analyst 360 | PR 53 branch `codex/align-staging-egress-gate` at `eaa172e`; open, mergeable, all reported checks green on 2026-07-25 | Reuse governed analytics, evidence, memory, decision/outcome, sole-founder controls, AWS IaC, and staging preflight. Keep stores separate. |
| Igloo multitenant conformance | Extensive host/community tests in `crates/buzz-test-client/tests/conformance_multitenant.rs` plus community-scoped services | Extend with Snowman proxy, adapter, cache, and adversarial launch cases. |
| Igloo release/build pipelines | Multi-platform desktop/mobile/container workflows and container provenance foundations | Fork to Snowman-owned registries, IDs, signing, SBOM/vulnerability policy, and endpoint gates; never deploy upstream artifacts directly. |
| Igloo agent/runtime catalog | Runtime-owned harness/provider/model capability metadata with desktop configuration surfaces | Extend for policy-approved model-per-role routing; do not fork capability facts into UI-only tables. |
| Igloo teams, personas, snapshots, nests, reminders, and workflow schedules | Proven local/control-plane foundations for scoped teams, per-agent runtime/model configuration, task continuity, collaboration, and scheduled triggers | Reuse for the Snowman AI Workforce experience. Add a durable AWS orchestration plane; local desktop processes alone do not satisfy 24/7 execution. |
| Igloo workflows/approvals | YAML workflows plus durable approval records and resume paths | Harden risk classification, role/capability approvers, unsupported actions, egress, idempotency, and evidence. |
| AWS Rust SDK for KMS | Pinned `aws-config` and `aws-sdk-kms` dependencies compile in the production relay library | Use Snowman-account KMS Verify for Analyst assertions and a distinct Snowman-account KMS Sign key for delivery receipts. No exportable signing key or Block service is introduced. |

## Snowman-controlled platform resources

| Platform | Approved use | Verification before mutation |
| --- | --- | --- |
| AWS | Compute, managed Postgres/Valkey/S3/KMS, IAM, secrets, logs, metrics, backups, budgets, DNS/TLS where selected | Validate active account/profile and exact Terraform plan. Prior referenced account: `625242091862`; prior profile: `snowman360-management-admin`. Do not assume identity from history. |
| Google Workspace | Workforce identity and approved Snowman collaboration/notification integration | Verify issuer/domain, OAuth application, groups/claims, admin ownership, lifecycle and audit settings. |
| Cloudflare | Snowman DNS/edge/WAF/access controls where already integrated | Verify Snowman account/zone, API token scope, origin policy, DNS records, logging, and direct-origin bypass protection. |

## Capabilities that must be added

- A Snowman model gateway at `models.snowmanai.org`, backed by a governed model
  catalog and a Snowman-hosted AWS inference fleet for strict zero-third-party
  processing. The clients now default to this authority, but the service itself
  is not yet deployed or proven.
- The Command Center AWS root now defines and validates the isolated managed
  substrate: three-AZ network layout, no NAT/private internet route, exact AWS
  endpoints, managed PostgreSQL, IAM-authenticated TLS Valkey, KMS/object-lock
  storage, encrypted logs, alarms, and budgets. Mock-provider plans cover dormant
  staging and production-HA invariants. The relay now has a tested streaming
  SigV4 provider with automatic reauthentication/resubscription and the
  Terraform root emits its password-free runtime contract. It has not been planned against or
  applied to a live Snowman account because the current AWS SSO session is
  expired; ECS workloads, ALB/WAF, backup vault lock, and recovery proof remain.
- The tenant-scoped Postgres workforce queue, fenced lease/recovery primitives,
  exact-snapshot approvals, capability-bound service identities, immutable
  context references, hard spend/token ledgers, aggregate request-state
  reconciliation, and a serialized secret-rejecting lifecycle-event hash chain
  now exist in source. AWS
  scheduler/worker services, sandbox isolation, proactive-policy evaluation,
  cancellation, and staged failure proof still must be built before
  the product can honestly provide 24/7 service.
- Governed human request intake and metadata-only status reads now exist at
  `/api/snowman/v1/work-requests`. The endpoint deliberately creates only a
  lead planning task. The private source boundary now leases that task, validates
  and atomically persists its specialist DAG, selects a best-fit approved model
  per role, and fences spend/completion. Provisioned private worker identities,
  catalog rows, AWS execution, and staged proof are still required end to end.
- A default-off, tenant-bound Analyst event ingress now verifies strict
  asymmetric KMS service assertions, rejects unknown or scope-mismatched fields,
  consumes replay nonces transactionally, stores only minimized lifecycle
  metadata and Analyst-authoritative artifact references, and returns a receipt
  signed by a separate Command Center KMS key. Analyst's outbox delivery worker,
  Analyst now also has a dedicated least-privilege delivery worker and ECS role
  in source. Private AWS routing, key provisioning/bindings, and staged
  two-tenant proof remain to be completed.
- Workforce identity/session/device/service schemas and fail-closed relay-key
  resolution now exist in source. The Snowman identity broker must still verify
  Google Workspace or AWS IAM Identity Center OIDC assertions and perform the
  enrollment, renewal, logout, rotation, and revocation flows end to end.
- A monitored alert destination. Technical setup can be automated, but inbox
  subscription confirmation remains user-owned when AWS requests it.
- For iOS distribution or push, a Snowman-controlled Apple Developer/APNs/App
  Store account and final agreements. Google Play/FCM can stay inside the
  approved Google boundary once the exact Snowman account is verified.

## Known user-owned gates

- Confirm a monitored notification subscription/inbox when the technical setup
  has been prepared and the exact endpoint is known.
- Approve a hosted external model processor if Snowman-hosted inference cannot
  meet a required quality/cost/latency target for a data class.
- Hold or approve platform-account actions that cannot be delegated, such as
  final app-store agreements and final production activation.

Everything else remains an engineering or evidence task and should be automated.

The Command Center AWS root now has an exact-version, exact-account,
digest-image, dormant-staging, production-HA, separate-Analyst-account, and
zero-external-model preflight. The latest read-only AWS identity call found the
configured SSO session expired, so this is source evidence only; no plan or
apply claim has been made.
