# Snowman Command Center

> Governed intelligence. Always advancing.

Snowman Command Center is the collaboration and agent-operations control plane
for Snowman 360. Humans and specialized AI agents work in tenant-isolated
channels, threads, projects, workflows, huddles, and governed work queues while
Analyst 360 remains the authority for client data, evidence, analytics, and
decision records.

This repository is the Snowman-maintained fork of the Apache-2.0 Buzz project.
The original copyright notice remains in [`LICENSE`](LICENSE); protocol and
package identifiers retained for compatibility are documented in
[`docs/snowman/branding-compatibility-register.md`](docs/snowman/branding-compatibility-register.md).
Snowman builds and runtime configuration do not require or connect to upstream
Block services.

## Product boundary

- **Snowman Command Center** coordinates requests, agent teams, work products,
  meetings, deadlines, approvals, and operational evidence.
- **Analyst 360** owns governed query execution, raw client data, evidence,
  recommendations, decisions, outcomes, and immutable artifacts.
- A narrow, versioned gateway exchanges tenant-scoped commands, status,
  evidence manifests, digests, citations, and immutable artifact references.
- Raw Aptive rows, transcripts, mailbox content, credentials, and unrestricted
  prompts do not enter the command-center data stores by default.

The current implementation and remaining launch gates are tracked in
[`docs/snowman/production-readiness-audit.md`](docs/snowman/production-readiness-audit.md)
and
[`docs/snowman/production-acceptance-criteria.md`](docs/snowman/production-acceptance-criteria.md).

## Capabilities

- Signed realtime channels, threads, DMs, canvases, media, search, and git
- Desktop, browser, mobile, operator, and CLI surfaces
- Specialist agent teams with scoped model grants and governed tool access
- Workflow scheduling, reminders, requests, approvals, and audit receipts
- Huddles and meeting-control foundations with consent and tenant gates
- Tenant-scoped memory and evidence-preserving Analyst 360 integration
- Snowman workforce identity, authorization, audit, and recovery controls

Capabilities are not production claims. A surface is production-ready only
after its acceptance criteria, staging drills, recovery evidence, and UAT pass.

## Architecture

```text
People / Snowman workforce identities
                 |
                 v
Snowman Command Center (experience and coordination plane)
   |             |                 |
   |             |                 +-- governed meeting/media adapters
   |             +-- scoped agent coordinator, model and tool gateways
   +-- versioned evidence-preserving API/events
                 |
                 v
Analyst 360 (client-data, evidence and decision-intelligence authority)
```

The relay uses Nostr-compatible signed events beneath the Snowman identity and
authorization layer. Event kinds, signed field names, `BUZZ_*` environment
variables, internal Rust crate/binary names, and read-only `buzz://` links may
remain where changing them would break signatures, automation, storage, or
upgrade compatibility. They are not product branding and do not authorize any
upstream network connection.

## Local development

Prerequisites: Docker, Rust 1.95, Node 24, pnpm 10, and `just`.

```bash
git clone https://github.com/xpxpxp-coder/Igloo.git
cd Igloo
. ./bin/activate-hermit
just setup
just dev
```

The default local relay listens on `ws://localhost:3000`. The root
[`docker-compose.yml`](docker-compose.yml) is a development stack only. AWS
production uses the separately reviewed Snowman infrastructure under
[`infra/aws`](infra/aws); it does not use the single-node Compose topology.

Useful checks:

```bash
just check
just test-unit
just test
node scripts/generate-snowman-product.mjs --check
node scripts/check-snowman-brand.mjs
node scripts/check-snowman-production-boundary.mjs
```

## Repository map

- `desktop/` — Tauri and React command center
- `web/` — browser experience
- `mobile/` — Flutter mobile client
- `admin-web/` — Snowman Operations dashboard
- `crates/` — relay, identity, agent, workflow, audit, media, CLI, and Snowman
  governance services
- `migrations/` — PostgreSQL schema and least-privilege runtime roles
- `infra/aws/` — private, default-dormant AWS deployment foundation
- `docs/snowman/` — architecture decisions, controls, runbooks, and launch
  evidence contracts

## Security and contribution

Report security issues to `security@snowmanai.org`. Do not include client data,
credentials, or private evidence in an issue.

Development conventions remain in [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`AGENTS.md`](AGENTS.md). Historical upstream documentation is retained where
it explains inherited protocols or implementation choices; Snowman production
decisions are authoritative only when recorded under `docs/snowman/`.

Licensed under Apache License 2.0. See [`LICENSE`](LICENSE).
