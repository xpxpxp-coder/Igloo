# Governed provider-egress proxy

Status: implemented and unit-tested as a fail-closed core; AWS packaging is
hard dormant. Live transport, identity, replay-store, DNS, TLS, cancellation,
provider, and recovery drills remain production-activation gates.

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

The production transport must satisfy all of these requirements before its
ECS service can be raised above zero:

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

AWS must route Secrets Manager access over a VPC endpoint. Public provider
egress is restricted to this security group and inspected DNS/HTTPS path; no
other Command Center workload receives equivalent public egress.

## Replay, cancellation, and evidence

The durable fence atomically claims `(request_id, request_digest)` against the
session generation. Reuse with different signed content is denied. Exact
replay never invokes the provider again and returns only the prior content-free
receipt. Cancellation is rechecked after claim, after DNS, and immediately
before dispatch. A cancellation or timeout racing an in-flight provider call
is recorded as sticky `indeterminate`; automatic retry is prohibited because
the remote side effect might have occurred.

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
- Redis/Valkey or PostgreSQL atomic claim, cancellation, and sticky
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
