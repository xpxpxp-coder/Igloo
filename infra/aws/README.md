# Snowman Command Center AWS deployment

This root is intentionally independent from Analyst 360. It will own separate
network, Postgres, Valkey, S3, KMS, secrets, queues, ECS roles/services, logs,
backups, and cost controls. Nothing in this root grants access to Analyst 360
stores; integration uses the private versioned API/event contracts only.

The current checked-in phase includes the account/image/activation preflight,
managed substrate, a dormant relay task contract, and per-identity dormant
workforce task/service contracts. It
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
topic, and an account-tag budget. The digest-pinned relay task definition runs
as non-root with a read-only root filesystem, dropped Linux capabilities,
writable scratch mounts, separate execution/task roles, exact ECR/log/secret,
Valkey, media-S3, and S3-via-KMS grants, and no ECS service that could activate
it. Each workforce profile has a distinct ECS execution role, task role,
Secrets Manager container, Nostr identity, Analyst service principal, and
cross-account asymmetric KMS signing key. Its task has no public IP, shell,
filesystem grant, shared agent secret, provider endpoint, or general internet
route; the only optional non-AWS egress is an exact private Analyst 360 prefix
list. Runtime secrets intentionally have no Terraform-managed values.
Staging uses one interface-endpoint ENI, one RDS instance, and one Valkey node;
production expands endpoints and managed state across availability zones.

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

The following resource layers still have to be added and proven before this
root is deployable:

1. ALB mutual origin authentication/WAF and proof that the Cloudflare-restricted
   origin security group has no alternate ingress path;
2. governed database-role/key bootstrap that populates the relay runtime secret,
   AWS Backup vault-lock plans, restore targets, CloudTrail/object-lock audit
   delivery, and tested recovery;
3. ECS relay service plus internal scheduler and sandbox; pinned specialist
   model images/weights and staged activation of the separate `aws-inference`
   endpoint/component root; private ingress
   for the now-defined model-gateway service; plus staged activation of the
   now-defined workforce services;
4. WAF, centralized encrypted logs/metrics/traces, alarms, synthetic probes,
   budgets, autoscaling, dormant staging controls, and evidence export; and
5. CI plan/policy tests, SBOM/provenance/signature enforcement, staged apply,
   recovery drills, UAT, rollback, and immutable launch evidence.

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
