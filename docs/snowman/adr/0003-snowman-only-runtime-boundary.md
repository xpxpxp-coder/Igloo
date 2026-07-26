# ADR 0003: Snowman-only runtime authority and egress

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Snowman AI sole-founder operator

## Decision

Production clients, services, workers, workflows, and agents may connect only to
Snowman-controlled surfaces. Snowman AWS accounts, Google Workspace, and
Cloudflare account/zone endpoints are part of the approved ecosystem when the
exact Snowman account, route, purpose, credential, and data class are bound by
policy. Block/Builderlab services, upstream relays, public Nostr relays, mutable
upstream images, arbitrary webhooks, and direct model-provider endpoints are
prohibited.

Public product traffic uses Snowman DNS. AWS service traffic uses private VPC
endpoints or explicitly inspected/allowlisted egress. Cloudflare must not leave
an unprotected direct-origin path. Desktop, browser, and mobile release builds
reject relay hosts outside `snowmanai.org`; development/test builds may use
loopback and fixtures. Agents have no ambient network authority. Approved
network access is an explicit capability and destination policy.

Strict model mode uses Snowman-hosted inference in AWS behind
`models.snowmanai.org`. A hosted external model cannot be smuggled into the
Snowman boundary merely by proxying it: it remains an external processor and
requires a provider/data-class decision in the dependency register.

Source provenance, license links, and package download locations may reference
upstream systems during controlled builds. They are not runtime authority.
Production deploys only reviewed, signed, digest-pinned Snowman artifacts.

## Enforcement

- `scripts/check-snowman-production-boundary.mjs` scans runtime authority files
  and pins required fail-closed controls.
- Release clients enforce Snowman relay DNS, TLS, and credential-free URLs.
- Workflow/model/tool policies enforce destination and capability boundaries.
- AWS infrastructure preflight rejects management-account deployment, shared
  Analyst 360 account/storage authority, mutable images, non-dormant staging,
  and external model processors by default.
- Staging must capture negative DNS/HTTP/WebSocket/redirect tests before launch.

## Consequences

Some inherited federation and self-host-anywhere UX is deliberately unavailable
in the Snowman product. The Snowman account/community provisioning service,
model gateway/inference fleet, and private AWS runtime must exist before those
flows can pass staging. This is preferable to silently streaming data to an
upstream or third-party surface.
