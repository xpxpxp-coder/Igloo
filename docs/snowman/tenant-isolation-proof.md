# Snowman tenant-isolation proof

Status: source-enforced and locally testable; live two-tenant staging evidence is
still a production activation gate.

## Authoritative tenant selector

For public Command Center traffic, the normalized direct HTTP `Host` header is
the only tenant selector. `Forwarded`, `X-Forwarded-Host`, and
`X-Original-Host` are untrusted metadata and never supply or override a tenant.
The shared `authoritative_host` seam is used before the security-critical
WebSocket, Analyst lifecycle-event, workforce identity, and workforce action
paths bind a community. Missing, invalid, unmapped, or lookup-failed Host input
fails closed without a default community.

This application rule is paired with deployment controls in `infra/aws`:

- Cloudflare-authenticated origin pull at the ALB;
- exact lowercase Snowman Host admission in WAF;
- ALB `preserve_host_header = true` and invalid-header dropping; and
- relay task ingress restricted to the ALB security group.

Forwarding headers may still carry client-address metadata for narrowly scoped
rate limiting. They are not identity or tenant authority.

## Proof matrix

| Boundary | Source-enforced property | Executable evidence |
| --- | --- | --- |
| Relay row zero | Direct Host resolves exactly one `TenantContext`; forwarded-host claims are ignored; empty/unmapped/lookup failure denies | `buzz-relay::tenant` unit tests and `conformance_multitenant::row_zero_host_binding` live tests |
| Nostr/HTTP collaboration | Connection state owns the immutable `TenantContext`; event, channel, workflow, search, media, pub/sub, cache, audit, and access queries carry `community_id` | Existing multi-tenant conformance suite plus relay and DB module tests |
| Analyst event ingress | Host-derived community is resolved before the tenant-local binding, nonce, signature, or event write | `api/analyst_integration.rs`; Analyst boundary tests |
| Human/workforce APIs | Host-derived community precedes session/capability checks and every request/task/status operation | `api/workforce_identity.rs`, `api/workforce.rs`, and workforce tests |
| One-shot agent broker | Route carries tenant UUID and every job read/update uses `(community_id, job_id)`; issuance joins task, request, lease, identity, and model inside one community | `snowman-agent-broker` tenant-first SQL test and migration composite keys |
| Agent coordinator | Launch, bootstrap, replay, cancellation, lease, and reconciliation queries retain tenant-first predicates and tenant-equal joins | `snowman-agent-coordinator` tenant-first SQL test and coordinator tests |
| Model gateway | Signed principal policy, model grant, request, job, task, lease generation, classification, capability, minimization digest, and budgets must all agree | `snowman-model-gateway::agent_authority_binds_every_live_scope_and_budget_coordinate` mutation test |
| Governed meetings | Calendar observation and admission must agree on tenant, workspace, mailbox, event revision, and sealed conference digest | `snowman-meeting-control::calendar_admission_is_exactly_tenant_revision_and_coordinate_bound` |

## Production acceptance gate

Before enabling production traffic, staging must record immutable evidence for
all of the following against two seeded tenants, including an Aptive-shaped
restricted tenant and a synthetic control tenant:

1. Run the ignored `conformance_multitenant` suite with two hostnames on the
   same relay, Postgres, and Valkey deployment. Include the forwarded-host
   spoof cases and direct-origin/alternate-Host attempts.
2. Attempt same-UUID and wrong-tenant reads, writes, receipts, cancellation,
   launch/bootstrap redemption, model generation, meeting schedule/cancel, and
   tool dispatch. Every attempt must deny without confirming other-tenant
   existence.
3. Exercise caches, reconnects, pub/sub fan-out, search, media, audit, backups,
   and restore into an isolated verification environment. Tenant labels and
   artifacts must remain partitioned after restart and recovery.
4. Capture ALB, WAF, security-group, route, RDS-role, and CloudTrail evidence
   proving there is no public bypass to private broker/coordinator/model/meeting
   services and no acceptance of an alternate Host authority.
5. Preserve test inputs, output digests, image/config attestations, timestamps,
   and reviewer acceptance in the launch-evidence manifest.

Until these live tests pass, the boundary is materially hardened in source but
must not be described as production-proven.
