# Snowman Command Center AWS deployment

This root is intentionally independent from Analyst 360. It will own separate
network, Postgres, Valkey, S3, KMS, secrets, queues, ECS roles/services, logs,
backups, and cost controls. Nothing in this root grants access to Analyst 360
stores; integration uses the private versioned API/event contracts only.

The current checked-in phase includes the account/image/activation preflight
and the managed substrate. It
fails before resource creation when the caller is in the wrong account, the
management account is targeted, production shares the Analyst 360 workload
account, the image is mutable or outside the exact Snowman ECR repository,
baseline staging is not dormant, production critical services are not HA, or
an external model processor is enabled. The substrate defines a three-AZ VPC,
Cloudflare-source-only edge security group, private ECS and isolated data
subnets with no NAT or internet default route, exact AWS interface/gateway
endpoints, managed PostgreSQL and IAM-authenticated TLS Valkey, object-locked
KMS-encrypted artifact/audit buckets, versioned deletable media storage,
asymmetric audit-signing KMS key,
enhanced ECS telemetry, encrypted service log groups, alarms, an SNS operations
topic, and an account-tag budget.
Staging uses one interface-endpoint ENI, one RDS instance, and one Valkey node;
production expands endpoints and managed state across availability zones.

The following resource layers still have to be added and proven before this
root is deployable:

1. ALB mutual origin authentication/WAF and proof that the Cloudflare-restricted
   origin security group has no alternate ingress path;
2. exact task configuration secrets, AWS Backup vault-lock plans, restore
   targets, CloudTrail/object-lock audit delivery, and tested recovery;
3. digest-pinned ECS relay, workforce worker, scheduler, sandbox, and internal
   model-gateway/inference services with distinct least-privilege roles;
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
password. The relay runtime must gain a short-lived SigV4 Valkey credential
provider and automatic reauthentication before its ECS service can be enabled;
the current Redis client path does not yet provide that production proof. This
is an engineering dependency, not a user approval.
