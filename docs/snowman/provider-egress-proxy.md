# Governed provider-egress proxy

Status: the fail-closed core now has a private HTTP runtime, AWS KMS workload
verification, tenant-RLS PostgreSQL replay/cancellation receipts, direct
DNS-pinned rustls transport, Secrets Manager credential injection, graceful
shutdown, bounded metrics, container packaging, and hard-dormant AWS ECS
foundations. Live provider, network-denial, database-fault, secret-rotation,
and recovery drills remain production-activation gates.

## Boundary

The provider-egress proxy is the only Snowman Command Center workload allowed
to make an approved meeting-provider API call. Meeting, orchestration, agent,
and tool services cannot receive a provider credential or select an endpoint.
They sign a bounded `snowman.provider-egress.request.v1` envelope containing:

- tenant and meeting-session IDs plus the exact session generation;
- authenticated service principal and unique replay key;
- one of `twilio`, `open_ai`, or optional `eleven_labs`;
- governed purpose, data classification, budget, deadline, and live policy
  generation;
- an operations-sealed destination ID, exact content type, and payload digest.

The caller cannot submit a URL, hostname, header, credential, proxy, redirect
policy, DNS answer, TLS name, or IP address. The sealed route configuration
maps the destination to exactly `api.twilio.com`, `api.openai.com`, or
`api.elevenlabs.io`, an exact path, an exact set of purposes/classifications,
bounded sizes and timeout, and an AWS Secrets Manager reference.

## Direct transport requirements

The runtime transport enforces the following requirements, which must still be
proven against the staged AWS network before its ECS service can be raised
above zero:

1. Disable environment/system proxy discovery and redirects.
2. Resolve the exact route hostname without search-domain expansion for every
   request. Reject an empty answer or the entire answer if any member is
   loopback, private, link-local, multicast, unspecified, documentation,
   carrier-grade NAT, benchmarking, reserved, or otherwise non-public.
3. Connect only to the validated result set. Validate the certificate for the
   route hostname and use that same hostname for TLS SNI and HTTP authority.
   Never use `CONNECT` or accept a provider-supplied redirect.
4. Fetch the exact JSON credential key from the exact same-account Secrets
   Manager ARN inside the transport. The secret must never enter a request,
   response, receipt, log, metric, trace, task-definition environment value,
   crash report, or caller-visible error.
5. Set the signed request ID as the provider idempotency key wherever the
   provider supports it. Enforce request, response, deadline, timeout, and
   concurrency ceilings before allocating unbounded buffers.

AWS routes Secrets Manager access over a VPC endpoint. The current ECS package
is deliberately unroutable to public providers: it stays in the private tier,
receives no public IP, and has no public HTTPS security-group rule or default
route. Application host sealing is defense in depth, not a substitute for
network-exact enforcement. Activation requires a separately reviewed AWS
Network Firewall domain-list route or Snowman Cloudflare egress-control path,
bound by `provider_egress_inspected_egress_evidence_sha256`. No other Command
Center workload may receive equivalent egress. Internal TLS ingress is
optional, disabled by default, and accepts only the meeting-media security
group through an internal NLB.

## Replay, cancellation, and evidence

The durable fence atomically claims tenant-scoped
`(community_id, request_id, request_digest)` against the
session generation. Both dispatch and cancellation require that exact
tenant/session/generation to be live in the meeting-media authority, and the
provider tables carry tenant-leading foreign keys back to that session. Reuse
with different signed content is denied. Exact
replay never invokes the provider again and returns only the prior content-free
receipt. Before the first provider byte can be sent, the runtime commits a
sticky `indeterminate` receipt marker. Cancellation is rechecked after claim,
after DNS, and immediately before dispatch. A crash, cancellation, or timeout
racing an in-flight provider call therefore cannot trigger an automatic retry,
because the remote side effect might have occurred.

The cancellation endpoint is itself KMS-signed and binds tenant, session,
generation, service principal, reason digest, issue time, and deadline. Each
database transaction sets `snowman.tenant_id`; PostgreSQL FORCE RLS repeats the
tenant boundary beneath application filtering. Receipt transitions are append
only, digest-only evidence and cannot represent provider content.

## Runtime contract

- `POST /v1/tenants/{tenant_id}/dispatch` accepts the exact envelope plus
  base64 payload/signature under a 12 MiB wire ceiling. Successful provider
  content exists only in the live response; replay returns the receipt alone.
- `POST /v1/tenants/{tenant_id}/sessions/{session_id}/generations/{generation}/cancel`
  writes the signed generation fence.
- `/_liveness`, `/_readiness`, and `/metrics` expose no tenant, provider body,
  URL, credential, prompt, transcript, or audio labels.

`SNOWMAN_PROVIDER_EGRESS_POLICY_JSON` is non-secret, operations-owned config.
It maps exact principals to same-account asymmetric KMS key ARNs and exact
dispatch/cancel capabilities and tenant grants. It maps
destination IDs to provider URLs, methods, tenant/purpose/classification and
budget bounds, response/request content types, and Snowman-named same-account
Secrets Manager ARNs. Provider credentials are never accepted through an
environment variable or caller field.

Terraform packaging lives in `infra/aws/provider_egress_proxy.tf`. It creates
nothing until runtime evidence, route policy, caller KMS keys, and provider
secret ARNs are supplied together. Even then, desired count is statically
restricted to zero and the task has no public provider route. Private TLS
ingress is a second default-off switch. Do not raise the service until the
inspected-egress path and its bypass-denial tests are represented in Terraform
and bound to immutable launch evidence.

Only `snowman.provider-egress.receipt.v1` may be persisted. It contains tenant,
session, generation, provider, purpose, classification, authorized budget,
policy generation, sealed destination ID, request/response digests and byte
count, status, and completion time. Raw audio, prompts, transcripts, email,
provider bodies, URLs, headers, and credentials are never written to the
fence, audit log, or telemetry. A successful response is transiently returned
only to the authenticated live caller; an exact replay cannot recover it.

## Activation evidence

The service stays at ECS desired count zero until staging proves:

- KMS-backed workload signature verification and tenant/principal denial;
- PostgreSQL FORCE-RLS atomic claim, cancellation, pre-send sticky
  indeterminate behavior under concurrent faults;
- pinned DNS and certificate/SNI enforcement, including mixed-answer DNS
  rebinding tests and redirect/proxy/`CONNECT` denial;
- Secrets Manager access for exactly the configured secret ARNs and no caller
  or adjacent task access;
- approved Twilio, OpenAI, and (if enabled) ElevenLabs sandbox calls with
  provider idempotency, cancellation, budgets, content types, and size limits;
- log/trace/crash inspection proving raw content and secrets are absent;
- Network Firewall/egress-DNS evidence proving Block, Square, arbitrary public
  hosts, private/reserved addresses, and non-proxy task egress are denied;
- replay, timeout, cancellation, secret rotation, provider outage, and task
  replacement recovery drills.

These tests are mandatory because the pure core deliberately uses injected
signature, resolver, transport, and fence interfaces and makes no live network
or AWS call during unit testing.
