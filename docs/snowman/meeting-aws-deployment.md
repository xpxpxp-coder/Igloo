# Meeting services: dormant AWS deployment contract

Status: **Terraform-packaged command service; media runtime deliberately absent
until executable and staged evidence exist; no AWS resources have been applied**.

The Command Center AWS root packages the meeting path as two separate private
services. Google Workspace mail and Calendar intake remains in Analyst 360 and
crosses the account boundary only through the signed, tenant-bound meeting
command contract. Neither service has a public address or a route to Block.

## Meeting-command service

The actual `snowman-meeting-command-service` binary is packaged as a small
ARM64 Fargate task with a read-only root, non-root UID, no shell capability,
private subnets, no public IP, and an exact two-task autoscaling ceiling. Its
execution role can pull only the digest-pinned Snowman Command Center image,
write its own encrypted log group, and read its own Secrets Manager container.
Its task role can only sign command receipts with the dedicated asymmetric KMS
key. It cannot read S3, call a model, send mail, place a call, assume another
role, or retrieve provider credentials.

The database secret must contain only the dedicated
`snowman_meeting_control` connection under the exact `DATABASE_URL` JSON key.
The runtime verifies that PostgreSQL identity and its restricted grants at
startup. Network policy allows only PostgreSQL, private AWS interface endpoints,
VPC DNS, and the meeting-media control service after that service is packaged.

Analyst 360 reaches meeting commands through an internal TLS Network Load
Balancer and an acceptance-required PrivateLink endpoint service. The allowlist
can contain only exact Analyst workload-account IAM principals. The local
Snowman workforce path is security-group-referenced; there is no CIDR ingress.
The NLB and split-horizon DNS remain cost-free by default because private
ingress is disabled.

## Meeting-media service

The provider-neutral media crate is not yet a server executable. Terraform
therefore creates no media task definition, service, Cloud Map namespace, IAM
execution role, or autoscaling target unless both of these immutable inputs are
present:

- a reviewed `/usr/local/bin/snowman-meeting-media-gateway` entrypoint; and
- a SHA-256 evidence digest covering executable provenance, consent fencing,
  callback authentication, tenant isolation, kill switches, raw-audio
  non-persistence, recovery, and staged UAT.

Even then, the checked-in desired count remains zero. The conditional task has
no AWS task role, no S3 permission, no model permission, no queue permission,
no provider credential, no public IP, and no direct internet route. It receives
only a dedicated `snowman_meeting_media` database URL, has a read-only root,
sets raw-audio retention to `none`, and is discoverable only through private
Cloud Map from the meeting-command security group. Its hard capacity ceiling is
four tasks.

External Twilio, OpenAI Realtime, and optional ElevenLabs traffic remains
disabled. A future reviewed media runtime may connect only to a separate
Snowman-owned provider-egress policy proxy on port 8443. Security groups never
allow `0.0.0.0/0`; the private service subnets have no NAT/default internet
route. The proxy contract accepts only exact `api.twilio.com`,
`api.openai.com`, and `api.elevenlabs.io` destinations and must independently
enforce DNS/TLS pinning, Snowman provider-account binding, tenant/data-class
policy, spend/duration limits, and redacted receipts. Provider callbacks and
media WebSocket ingress are intentionally not present in this slice.

## Activation gates

Both ECS desired counts are hard-zero in baseline preflight, the external
provider switch is false, and the cost-bearing command NLB is absent. Before a
reviewed staging verification window can change those locks, launch evidence
must include:

1. an immutable image/SBOM/provenance/signature/vulnerability bundle containing
   the exact executable;
2. dedicated database-role bootstrap and privilege-denial proof;
3. cross-account PrivateLink acceptance, signed request/replay, wrong-tenant,
   stale-revision, cancellation-fence, and receipt-verification tests;
4. authenticated Twilio/OpenAI callback adapters and the separately deployed
   Snowman provider-egress proxy, if external routes are enabled;
5. raw audio absent from PostgreSQL, S3, logs, traces, crash artifacts, and
   backups, with any transcript reference resolving only through Analyst 360;
6. consent/disclosure, participant-change pause, cost/duration kill-switch,
   recovery, accessibility, latency, quality, and rollback UAT; and
7. monitored alarm delivery plus current sole-founder activation acceptance.

The AWS plan is safe to inspect without Google, Twilio, OpenAI, or ElevenLabs
credentials. Creating the dedicated Workspace identity, authorizing each
provider account, confirming the monitored alert subscription, and accepting
final activation remain operator-owned actions at the end of staged proof.
