# Snowman Command Center AWS deployment

This root is intentionally independent from Analyst 360. It will own separate
network, Postgres, Valkey, S3, KMS, secrets, queues, ECS roles/services, logs,
backups, and cost controls. Nothing in this root grants access to Analyst 360
stores; integration uses the private versioned API/event contracts only.

The current checked-in phase is the account/image/activation preflight. It
fails before resource creation when the caller is in the wrong account, the
management account is targeted, production shares the Analyst 360 workload
account, the image is mutable or outside the exact Snowman ECR repository,
baseline staging is not dormant, production critical services are not HA, or
an external model processor is enabled.

The following resource layers still have to be added and proven before this
root is deployable:

1. isolated multi-AZ VPC, Cloudflare-restricted public ingress, no direct-origin
   bypass, private service endpoints, and inspected destination allowlists;
2. managed Postgres/Valkey, object-locked artifact/audit buckets, KMS keys,
   Secrets Manager, queues/DLQs, backup/PITR, and restore targets;
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
