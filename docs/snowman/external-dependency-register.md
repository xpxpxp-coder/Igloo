# External dependency and data-egress register

Status: discovery in progress; no production processor is approved by this file.

## Policy

Snowman production has no ambient internet access. A dependency is allowed only
when Snowman controls the account/configuration, the destination and purpose are
explicit, the minimum data classes are documented, credentials are isolated,
traffic is auditable, and a disable/fail-closed path exists. Block-operated
services are prohibited. Source-code provenance references do not authorize
runtime traffic.

## Current register

| Dependency class | Why it may be necessary | Default production decision | Data boundary and required evidence |
| --- | --- | --- | --- |
| Snowman AWS accounts | Compute, network, managed data services, KMS, backups, logs | Approved Snowman ecosystem, required | Separate Command Center/Analyst roles and stores; account/region/resource inventory; CloudTrail and egress evidence. |
| Snowman Google Workspace | Human SSO, lifecycle, and approved collaboration/notification surfaces | Approved Snowman ecosystem | Stable subject, tenant/role claims, auth strength and minimum delivery metadata; no client work product unless a separately governed workflow expressly permits it. |
| Snowman account and community provisioning service | Workforce login, cryptographic identity binding, and Snowman-managed community lifecycle | Required and not yet deployed at `accounts.snowmanai.org`; inherited Builderlab endpoint is prohibited and has been removed from runtime authority | Snowman Google Workspace/AWS identity broker, short-lived sessions, device binding, tenant-scoped provisioning, CloudTrail/audit receipts, revocation and recovery evidence. |
| Snowman Cloudflare account | Snowman-controlled DNS, edge security, and approved public ingress | Approved Snowman ecosystem | Snowman zones/routes only; configuration export, access logs, TLS/origin policy, and bypass tests required. |
| Foundation model inference | Specialist agent reasoning and generation | Self-hosted Snowman AWS inference is the only zero-third-party-data-egress default. Hosted providers require a separately approved connector. | Per-model/provider allowlist, prompt field classification, redaction/minimization, tenant policy, retention/training terms, regional routing, request/response receipts, kill switch. |
| Snowman model gateway and inference fleet | Enforce per-agent best-fit model policy without exposing vendor endpoints or credentials to clients/workers | Required and not yet deployed/proven. Gateway must be Snowman-controlled; zero-third-party mode uses models hosted in Snowman AWS. | Tenant/data-class policy, per-route receipts, credentials only in the broker, model catalog, evaluation results, budgets, throttles, kill switch, negative direct-egress test. |
| Snowman durable agent runtime | Run scheduled and proactive specialist work safely when user devices are offline | PostgreSQL queue/leases and isolated managed AWS substrate now exist in source; worker, scheduler, sandbox, credential broker, deployment, and proof remain required | Tenant-bound queues/workers, lease/heartbeat, idempotency, sandbox, scheduler, recovery, dead-letter policy, cost ceilings, audit correlation, dormant staging controls. |
| Analyst 360 private service boundary | Submit governed commands and return minimized job/evidence-reference lifecycle events without shared stores | Bidirectional application contracts and the least-privilege Analyst delivery worker now exist in source; private AWS routing, asymmetric KMS key provisioning, bindings, and staged proof remain incomplete | Exact tenant/client/project binding, canonical request digests, one-time nonces, separate request/receipt keys, content-addressed Analyst-authoritative references, no raw Aptive rows/transcripts, and no public or Block endpoint. |
| DNS and public TLS | Public Snowman names and trusted HTTPS | Required under Snowman-controlled AWS/Cloudflare domains and accounts | Public hostname and certificate metadata only; registrar/DNS/ACM/Cloudflare ownership evidence. |
| Email/notification delivery | Alerts, reminders, invitations | Not approved until a Snowman-controlled destination/provider and data-minimized templates are selected | Recipient/address, event class, bounded notification content; no raw Aptive data; delivery and unsubscribe evidence. |
| Mobile push and app stores | Native mobile notifications/distribution | Optional; disabled until Snowman-owned Apple/Google accounts and privacy decisions are complete | Opaque device capabilities and minimized notification content; platform-account and release-signing evidence. |
| Source and package registries | Build inputs and release distribution | Runtime prohibited. Build-time upstream retrieval is quarantined; production deploys only Snowman-owned signed digests. | Lockfiles, SBOM, provenance, vulnerability policy, mirrored artifact digest, signature verification. |
| Block-operated Buzz services | Upstream relay, image, chart, push, pairing, updates, downloads, telemetry | Prohibited | Automated endpoint inventory and negative egress tests must show zero production reachability. |

## Decision rule for hosted models

The product requirement for best-fit per-agent models conflicts with a literal
zero-third-party-data-egress rule when the best model is available only as a
hosted API. Until the user accepts a provider-specific processing boundary, the
system must choose a Snowman-hosted model or refuse that task rather than silently
send data. Model routing optimizes quality only within the tenant's approved
provider and data-class policy.

Clients, desktop runtimes, and specialist workers are never permitted to call a
model vendor directly. Even if an external processor is later approved, the
Snowman gateway remains the only client-visible route and holds the connector
credential. Approval of a hosted processor is not approval of ambient internet
egress.

## Exit criteria

Before production activation, every row is either linked to immutable approval
and test evidence or marked disabled with a passing network-denial test. Any new
destination blocks release until this register and the egress policy are updated.
