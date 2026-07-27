# ADR 0005: ACP execution arm and optional runtime adapters

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Snowman AI sole-founder operator

## Decision

Snowman's execution arm is the runtime-neutral ACP harness already present in
the Command Center. It accepts governed work from the durable workforce plane,
starts an explicitly registered specialist runtime, selects the exact approved
model for that role and data class, supplies a bounded context manifest, and
returns lifecycle evidence and immutable artifact references.

OpenClaw and Hermes are not current Igloo dependencies and are not privileged
Snowman authorities. Either may later be registered as an optional ACP adapter
or wrapped behind one when it provides a measured capability that the native
Snowman runtimes lack. Registration requires a pinned artifact, provenance,
SBOM/signature, compatibility tests, role-specific quality evaluation, resource
limits, capability declarations, and the same revocation/audit controls as any
other runtime. No adapter may weaken Snowman policy or introduce its own relay,
cloud, telemetry, memory, credential, plugin, update, or publishing channel.

Production specialists execute remotely in a Snowman AWS sandbox. The desktop,
web, and mobile apps are command, consent, observation, and artifact surfaces;
they are not trusted production sandboxes for autonomous shell/network work.
The execution environment has no public route, uses scoped mounts and a unique
service identity, receives no ambient human/relay/cloud/provider credential,
and reaches only private Snowman relay, artifact, and model-gateway endpoints
per its capability policy. Local desktop ACP execution remains a development
surface until an OS-level containment profile passes the production adversarial
suite.

Raw Aptive rows, transcripts, identifiers, credentials, and unrestricted query
results remain inside Analyst 360. An agent receives only a minimized,
classification-labeled, tenant-bound context packet or an independently
authorized immutable reference. Incoming public or connector content is always
untrusted data, even when the source is allowlisted; it cannot grant tools,
change policy, select destinations, reveal secrets, or bypass approvals.

## Enforcement

- The ACP subprocess receives no relay signing key, owner attestation, cloud
  credential, direct provider key, or self-issued shell/network capability.
- Codex tool subprocesses receive a final `network_access=false` overlay that
  parent and persona configuration cannot widen. Other runtimes require the
  external Snowman AWS network sandbox before production eligibility.
- MCP receives a relay address only. Signed actions must use a future
  purpose-specific action broker with an exact task lease and capability; the
  general agent tool plane never receives a relay nsec.
- Model routes are selected from the tenant/data-class catalog and resolve only
  to Snowman's private model gateway or approved self-hosted inference fleet.
- Unknown adapters, direct vendor endpoints, ambient configuration directories,
  arbitrary remote plugins, and runtime self-updates fail production preflight.

## Consequences

The ACP layer can support a broad and evolving team of specialist agents without
making one framework the platform. Some inherited local-agent convenience is
intentionally unavailable in production until equivalent brokered operations
exist. Capability expansion occurs by adding a narrow, evaluated runtime or
broker action—not by granting a general-purpose agent unrestricted access.
