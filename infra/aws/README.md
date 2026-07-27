# Snowman Command Center AWS deployment

This root is intentionally independent from Analyst 360. It will own separate
network, Postgres, Valkey, S3, KMS, secrets, queues, ECS roles/services, logs,
backups, and cost controls. Nothing in this root grants access to Analyst 360
stores; integration uses the private versioned API/event contracts only.

The current checked-in phase includes the account/image/activation preflight,
managed substrate, a hard-dormant relay service, per-identity workforce
task/service contracts, a separate maintenance scheduler, recurring trigger,
and fixed-content in-product reminder service. It
also defines credentialless, one-shot ACP agent task definitions and a distinct
deny-by-default executor/broker network boundary. The matching one-shot
executor client exists in source, but no reviewed adapter image, action tools,
model-token path, or agent service is active. The private job broker
exists in source and in a hard-dormant ECS deployment contract: a protected
internal TLS NLB, executor-SG-only ingress, split-horizon Snowman DNS, a
task-role-free non-root service, and database-only application egress. This root
also defines a separate KMS-encrypted broker runtime secret populated only by
the one-shot bootstrap; no relay task can read that secret, and the broker
execution role reads only its `database_url` field. A separate hard-dormant
coordinator now provides NIP-98/service-key-bound launch, KMS HMAC job-token
derivation, exact revision-scoped ECS authority, crash/expiry/cancellation
reconciliation, worker-only internal TLS ingress, and RDS/private-AWS-endpoint
egress. It cannot access the relay, Analyst, model, artifact, connector, or
public network. It
fails before resource creation when the caller is in the wrong account, the
management account is targeted, production shares the Analyst 360 workload
account, the image is mutable or outside the exact Snowman ECR repository,
any runtime desired count is nonzero before its remaining gates, or an external
model processor is enabled. The substrate defines a three-AZ VPC,
Cloudflare-source-only edge security group, private ECS and isolated data
subnets with no NAT or internet default route, exact AWS interface/gateway
endpoints, managed PostgreSQL and IAM-authenticated TLS Valkey, object-locked
KMS-encrypted artifact/audit buckets, versioned deletable media storage,
asymmetric audit-signing KMS key,
enhanced ECS telemetry, encrypted service log groups, alarms, an SNS operations
topic, an account-tag budget, a redacted service-error dashboard, an immutable
KMS-encrypted Snowman ECR repository, and a dedicated asymmetric release-signing
key. A separate fail-closed launch-evidence preflight binds any future runtime
activation to the exact image and current immutable restore, audit, telemetry,
alert, rollback, cost, isolation, vulnerability, and final-acceptance evidence.
Meeting media, orchestration, and provider egress also have explicit
service-specific launch-report digests and unexpected-running alarms. The
global activation preflight treats their ingress, inspected-network, and
desired-count switches as activation requests.

`release_assurance.tf` asserts encrypted RDS PITR, preserved automated/final
snapshots, encrypted Valkey snapshot retention, and versioned COMPLIANCE-locked
audit evidence. These source assertions are prerequisites, not restore proof;
the immutable launch bundle must include clean-target migration/PITR rehearsal.
The digest-pinned relay task definition runs
as non-root with a read-only root filesystem, dropped Linux capabilities,
writable scratch mounts, separate execution/task roles, exact ECR/log/secret,
Valkey, media-S3, and S3-via-KMS grants. Its ECS service is fixed at zero by both
input preflight and resource precondition. Each workforce profile has a distinct
ECS execution role, task role,
Secrets Manager container, Nostr identity, Analyst service principal, and
cross-account asymmetric KMS signing key. Its task has no public IP, shell,
filesystem grant, shared agent secret, provider endpoint, or general internet
route; the only optional non-AWS egress is an exact private Analyst 360 prefix
list. The maintenance scheduler, recurring trigger, and reminder worker each
have a distinct identity, empty AWS task role, and no Analyst/model network
path. The reminder worker accepts no recipient or message body. Private
workforce services reach the exact Snowman hostname through split-horizon Route
53 and an internal TLS ALB; the
public WAF blocks `/internal/`. Runtime secrets intentionally have no
Terraform-managed values.
Staging uses one interface-endpoint ENI, one RDS instance, and one Valkey node;
production expands endpoints and managed state across availability zones.

The one-shot bootstrap now receives a Terraform-generated, non-secret workforce
manifest. It creates or verifies the exact Snowman community, generates and
preserves one service key per identity only in that identity's Secrets Manager
container, writes the shared team map into worker secrets, reconciles exact
role-derived grants and evaluated Snowman model routes, and records only a
manifest digest in PostgreSQL/logs. Terraform and task definitions never contain
private keys. A live staging bootstrap/rerun/revocation test is still required.

When the workforce APIs are deliberately activated, Terraform requires the
lead identity to match a configured worker profile plus an exact Snowman model
gateway URL and planning-model catalog ID. Automatic capabilities remain an
explicit empty-by-default set with separate cost and confidence ceilings;
adding `deadline.remind` is required for ungated reminder execution.

The model gateway has a default-off cross-account PrivateLink provider contract:
an internal TLS Network Load Balancer, exact Snowman ACM certificate, endpoint
service with acceptance required, and an exact Analyst-account IAM-principal
allowlist. The NLB has no CIDR ingress and can forward only to the gateway
security group. Its endpoint service name and private-DNS verification state are
exported for the separate Analyst root; no VPC peering, public model endpoint,
or shared data tier is introduced.

The gateway can also invoke exact same-account SageMaker endpoint ARNs through
the private `sagemaker.runtime` interface endpoint. The task role receives no
SageMaker wildcard permission, and configured routes cannot name a public model
provider URL. This is the private execution path for Snowman-hosted specialist
models; model images, weights, endpoint capacity, evaluations, and autoscaling
are a separate still-dormant layer and are not implied by this substrate.

The meeting-command service is packaged as a separate, hard-dormant private
Fargate service. It uses an acceptance-required Analyst-only PrivateLink
endpoint, exact Snowman TLS/DNS identity, a dedicated PostgreSQL runtime secret,
receipt-only asymmetric KMS task authority, encrypted logs/alarms, and a
two-task cost ceiling. It has no provider, mail, model, object-store, relay, or
public network authority. The meeting-media service is more restrictive: no
task definition or service exists until a real executable entrypoint and staged
runtime evidence digest are supplied. Its prospective task has no AWS task
role, object persistence, provider credential, public ingress, NAT, or direct
internet route. Optional provider traffic can reach only a separately reviewed
Snowman policy-proxy security group, and remains default-off. See
`docs/snowman/meeting-aws-deployment.md` for the exact activation evidence.

The following resource layers still have to be added and proven before this
root is deployable:

1. ALB mutual origin authentication/WAF and proof that the Cloudflare-restricted
   origin security group has no alternate ingress path;
2. live proof of the implemented database/runtime/workforce bootstrap;
   clean-target RDS PITR, Valkey snapshot, S3 version, KMS checkpoint, and
   object-lock recovery drills using the checked-in recovery runbook;
3. staged recurring-trigger lost-response/restart proof; the agent runtime
   image, broker action catalog, model-token path, worker/coordinator completion wiring, and live sandbox
   adversarial proof; pinned specialist model images/weights and staged
   activation of the separate `aws-inference`
   endpoint/component root; private ingress for the now-defined model-gateway
   service; plus staged activation of relay, workforce, and scheduler services;
4. staged proof of the configured WAF, encrypted logs/metrics, alarms,
   Snowman-only trace export, private synthetic probes, budgets, autoscaling,
   dormant controls, redaction, and evidence retention; and
5. the Snowman OIDC-to-ECR production builder, generated SBOM/provenance/KMS
   signatures, staged apply, recovery drills, UAT, rollback, and a passing
   version-bound `snowman.launch-evidence.v1` manifest.

Terraform is pinned to the same exact tool/provider versions already governed
in Analyst 360. Do not run `apply` from a management profile or with example
account IDs. The currently configured AWS SSO session was expired at the latest
read-only identity check, so no AWS mutations have been attempted from this
branch.

The Valkey substrate deliberately uses IAM authentication rather than a static
password. `snowman-aws-auth` generates 15-minute SigV4 tokens from the ECS task
role; the shared Redis boundary refreshes them every ten minutes,
reauthenticates live connections, reconnects, and restores RESP3 subscriptions.
`valkey_runtime_contract` emits the exact non-secret environment and the two
resources an ECS task role must receive under `elasticache:Connect`. The IAM
user is restricted to `buzz:*` keys/channels and the commands the relay and mesh
actually use; it does not receive `+@all`.
