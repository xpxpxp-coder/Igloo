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
| Snowman product identity layer | Canonical product/design JSON, deterministic generators, generated desktop/web/admin/mobile bindings, vector and platform icons, and automated surface/boundary checks exist on the working branch | Use this authority for every supported surface; keep upstream names only where the compatibility register identifies a wire, process, or migration requirement. |
| Igloo teams, personas, snapshots, nests, reminders, and workflow schedules | Proven local/control-plane foundations for scoped teams, per-agent runtime/model configuration, task continuity, collaboration, and scheduled triggers | Reuse for the Snowman AI Workforce experience. Add a durable AWS orchestration plane; local desktop processes alone do not satisfy 24/7 execution. |
| Igloo workflows/approvals | YAML workflows plus durable approval records and resume paths | Harden risk classification, role/capability approvers, unsupported actions, egress, idempotency, and evidence. |
| AWS Rust SDK for KMS | Pinned `aws-config` and `aws-sdk-kms` dependencies compile in the production relay library | Use Snowman-account KMS Verify for Analyst assertions and a distinct Snowman-account KMS Sign key for delivery receipts. No exportable signing key or Block service is introduced. |

Relay, push-gateway, and Helm publishers now default only to the
`snowman-ai-org` registry namespace, verify attestations against that owner,
and label images with the Snowman source repository. Production Terraform still
requires a Snowman-account ECR digest. Creation/control of the final Snowman
Command Center GitHub repository/package permissions and Apple/mobile signing
identities remains owner-held. Every active release/canary repository guard is
now Snowman-owned, and macOS jobs fail closed before signing until the Snowman
mechanism exists; no Block action or registry remains in deployment workflows.

The desktop webview now enforces a Snowman-only production CSP. MediaPipe avatar
segmentation no longer falls back to public CDNs: releases resolve the WASM and
model only from packaged same-origin paths. The pinned model has not yet been
mirrored into Snowman's artifact pipeline, so background removal currently
fails locally to the normal unsegmented recording path rather than making an
undeclared network request.

Production desktop builds expose only the bundled Snowman Agent runtime. The
upstream Codex, Claude, and Goose harness adapters remain available solely in
debug builds for compatibility testing because their vendor CLIs can establish
provider-direct connections. Production per-agent model selection therefore
routes only through `models.snowmanai.org`; enabling any hosted third-party
processor requires a separately approved Snowman gateway route and data-flow
record, not a client-side API key or direct vendor CLI.

## Snowman-controlled platform resources

| Platform | Approved use | Verification before mutation |
| --- | --- | --- |
| AWS | Compute, managed Postgres/Valkey/S3/KMS, IAM, secrets, logs, metrics, backups, budgets, DNS/TLS where selected | Validate active account/profile and exact Terraform plan. Prior referenced account: `625242091862`; prior profile: `snowman360-management-admin`. Do not assume identity from history. |
| Google Workspace | Workforce identity and approved Snowman collaboration/notification integration | Verify issuer/domain, OAuth application, groups/claims, admin ownership, lifecycle and audit settings. |
| Cloudflare | Snowman DNS/edge/WAF/access controls where already integrated | Verify Snowman account/zone, API token scope, origin policy, DNS records, logging, and direct-origin bypass protection. |

## Capabilities that must be added

- A private Snowman model gateway is now implemented and locally tested. It
  accepts only exact KMS-signed Analyst requests, revalidates tenant, role,
  capability, classification, model and budgets, consumes replay nonces in a
  dedicated least-privilege Valkey namespace, and can route only to private
  Snowman origins or exact same-account SageMaker endpoints through a VPC
  interface endpoint. Its dormant ECS service/task and exact IAM/network
  boundaries exist in source. A separate hard-dormant inference root now defines
  network-isolated, digest-pinned SageMaker model/component coordinates,
  object-locked weights, per-model identities, scale-to-zero, cold-start wake
  alarms, and bounded capacity. Pinned model images/weights, role evaluations,
  usage reconciliation, deployment, and live zero-egress proof remain.
  A default-off PrivateLink provider with Snowman TLS, endpoint acceptance, and
  exact Analyst-account principals now implements the cross-account ingress
  substrate; live certificate/DNS verification, endpoint acceptance, and
  connectivity proof remain.
- The Command Center AWS root now defines and validates the isolated managed
  substrate: three-AZ network layout, no NAT/private internet route, exact AWS
  endpoints, managed PostgreSQL, IAM-authenticated TLS Valkey, KMS/object-lock
  storage, encrypted logs, alarms, and budgets. Mock-provider plans cover dormant
  staging and production-HA invariants. The relay now has a tested streaming
  SigV4 provider with automatic reauthentication/resubscription and the
  Terraform root emits its password-free runtime contract. It has not been planned against or
  applied to a live Snowman account because the current AWS SSO session is
  expired. A digest-pinned, non-root, read-only relay task definition, ECS
  service, and exact roles now exist but are hard-dormant under layered zero-count
  preconditions. A separate one-shot
  bootstrap task now runs embedded migrations, reconciles a no-DDL/DML-only
  serving role, generates relay/HMAC material outside Terraform, verifies the
  serving identity, and writes only the exact KMS-encrypted runtime JSON secret.
  Its execution still requires an enrolled Snowman owner public key and live
  staging evidence. A default-off Cloudflare-CIDR plus Snowman-specific mTLS,
  exact-host WAF, governed-log ALB edge now exists in source and passes dormant,
  enabled-edge, and production-HA mock plans; its Cloudflare certificate/DNS and
  live bypass proof remain. Recurring partition rotation, worker/model services,
  backup vault lock, and recovery proof remain.
- The tenant-scoped Postgres workforce queue, fenced lease/recovery primitives,
  exact-snapshot approvals, capability-bound service identities, immutable
  context references, hard spend/token ledgers, aggregate request-state
  reconciliation, and a serialized secret-rejecting lifecycle-event hash chain
  now exist in source. AWS
  per-identity worker services, a maintenance-only scheduler service, private
  TLS ingress, and split-horizon DNS are now hard-dormant in AWS source. Sandbox
  isolation and staged failure/recovery proof still must pass before the product
  can honestly provide 24/7 service.
- Proactive next-useful actions now have a tenant-scoped durable decision store:
  authorized service proposer, source-event/action/policy/usefulness digests,
  risk/reversibility/confidence, schedule/expiry, exact idempotency, and cost
  reservation against the originating request. Supported v2 decisions now
  materialize as ordinary governed work tasks and reuse fenced leases,
  approvals, spend, cancellation, context, recovery, and evidence; the
  maintenance scheduler expires stale actions. A trigger poller,
  calendar/reminder delivery capabilities, notifications, and staged 24/7 proof
  remain.
- A deterministic context-manifest policy now gives replacement specialists a
  bounded, classified, content-addressed handoff contract with objective,
  provenance, evidence/artifact references, decision/open-question digests, and
  governed next actions. Tenant-scoped, idempotent persistence now verifies an
  active `workforce.context.write` service identity, matches the request's
  objective/classification, stores only the bounded manifest plus immutable
  artifact coordinates, and appends `context.published` evidence. The private
  API now publishes and lists non-expired manifests only for an active assigned
  service identity with the exact read/write capability; it never returns the
  artifact body. Staged replacement-agent and artifact-authority retrieval proof
  remain.
- Governed human request intake and metadata-only status reads now exist at
  `/api/snowman/v1/work-requests`. The endpoint deliberately creates only a
  lead planning task. The private source boundary now leases that task, validates
  and atomically persists its specialist DAG, selects a best-fit approved model
  per role, and fences spend/completion. An identity-isolated durable worker now
  claims and heartbeats tasks, commits the default specialist/reviewer DAG,
  dispatches exact model-bound Analyst commands, polls verified status, publishes
  context manifests, and completes from immutable artifact evidence. Provisioned
  identities/catalog rows, capability-specific Analyst executors, AWS execution,
  and staged proof are still required end to end.
- A default-off, tenant-bound Analyst event ingress now verifies strict
  asymmetric KMS service assertions, rejects unknown or scope-mismatched fields,
  consumes replay nonces transactionally, stores only minimized lifecycle
  metadata and Analyst-authoritative artifact references, and returns a receipt
  signed by a separate Command Center KMS key. The outbound Command Center client
  now submits only allowlisted tenant-bound commands using one-time exact-body KMS
  assertions, rejects redirects/proxies/non-Snowman hosts, and verifies Analyst
  receipt/event digests. Analyst also has a dedicated least-privilege delivery
  worker and ECS role in source. Private AWS routing, key provisioning/bindings,
  capability-specific workers, and staged two-tenant proof remain to be completed.
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
