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
| Snowman workforce identity authority | Workforce login, cryptographic identity binding, and Snowman-managed community lifecycle | Analyst 360 implements privacy-preserving Google Workspace/KMS enrollment, signed session/global/identity revocation, and an isolated crash-fenced retry worker in source; it is private, default-off, and not deployed. Inherited Builderlab/Block identity endpoints remain prohibited. | Short-lived, tenant-scoped KMS assertions; pseudonymous subject digest; Nostr device proof; no provider token/email/raw subject; current MFA-policy evidence; retry/recovery deployment, private-routing, and staging evidence remain required. |
| Snowman Cloudflare account | Snowman-controlled DNS, edge security, and approved public ingress | Approved Snowman ecosystem. A default-off ALB/WAF/mTLS edge contract now exists in source; the Snowman hostname-specific origin client certificate and live Cloudflare configuration are not yet proven. | Snowman zones/routes only; custom zone/hostname AOP certificate, pinned CA digest, reviewed IP ranges, configuration export, access logs, TLS/origin policy, and direct-bypass tests required. |
| Foundation model inference | Specialist agent reasoning and generation | Self-hosted Snowman AWS inference is the only zero-third-party-data-egress default. Hosted providers require a separately approved connector. | Per-model/provider allowlist, prompt field classification, redaction/minimization, tenant policy, retention/training terms, regional routing, request/response receipts, kill switch. |
| Snowman model gateway and inference fleet | Enforce per-agent best-fit model policy without exposing vendor endpoints or credentials to clients/workers | The locally tested gateway and hard-dormant fleet IaC support only private Snowman origins or exact same-account SageMaker endpoint/components through private AWS networking. Images, weights, evaluations, deployment, and staged proof remain; zero-third-party mode uses only models hosted in Snowman AWS. | Tenant/data-class policy, exact endpoint/component IAM, VPC endpoint path, network-isolated containers, pinned image/weight provenance, per-route receipts, evaluation results, budgets, cold-start retries, throttles, kill switch, negative direct-egress test. |
| Snowman durable agent runtime | Run scheduled and proactive specialist work safely when user devices are offline | PostgreSQL queue/leases, identity-isolated workers, v2 proactive-to-task materialization, an idempotent deadline/recovery scheduler, a separately scoped recurring trigger, recipient/message-denying in-product reminders, credentialless one-shot Fargate task definitions, the executor client, shared strict job contracts, and the private digest/idempotency-enforcing broker service now exist in source. Broker/coordinator role provisioning and deployment, the model-token/action-tool paths, optional adapter images, activation, and staged proof remain required. | Tenant-bound queues/workers, lease/heartbeat, deterministic schedule claims and reminder receipts, idempotency, no ECS task role, pinned runtime/SBOM/provenance/evaluation digests, deny-by-default private egress, digest-verified job snapshots, constant-time opaque-token verification, exact broker receipts, recovery, retention/purge, dead-letter policy, cost ceilings, audit correlation, dormant staging controls. |
| Analyst 360 private service boundary | Submit governed commands and return minimized job/evidence-reference lifecycle events without shared stores | Bidirectional application contracts and the least-privilege Analyst delivery worker now exist in source; private AWS routing, asymmetric KMS key provisioning, bindings, and staged proof remain incomplete | Exact tenant/client/project binding, canonical request digests, one-time nonces, separate request/receipt keys, content-addressed Analyst-authoritative references, no raw Aptive rows/transcripts, and no public or Block endpoint. |
| DNS and public TLS | Public Snowman names and trusted HTTPS | Required under Snowman-controlled AWS/Cloudflare domains and accounts | Public hostname and certificate metadata only; registrar/DNS/ACM/Cloudflare ownership evidence. |
| Email/notification delivery | Optional off-platform alerts and invitations | Not approved until a Snowman-controlled Google Workspace destination and data-minimized templates are selected. In-product kind `40007` reminders require no external delivery provider. | Recipient/address, event class, bounded notification content; no raw Aptive data; delivery and unsubscribe evidence. |
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
