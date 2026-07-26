# Snowman Command Center production program

This directory is the decision and acceptance record for the Snowman-branded
command center derived from Buzz. It is intentionally stricter than the
upstream self-hosting documentation.

Current decision: **adopt with hardening; do not activate production yet**.

- [Source-level maturity audit](production-readiness-audit.md)
- [ADR 0001: separate command-center control plane](adr/0001-separate-command-center-control-plane.md)
- [ADR 0002: governed, durable AI workforce](adr/0002-governed-ai-workforce.md)
- [ADR 0003: Snowman-only runtime and egress](adr/0003-snowman-only-runtime-boundary.md)
- [ADR 0004: private specialist model fleet](adr/0004-private-specialist-model-fleet.md)
- [Production acceptance criteria](production-acceptance-criteria.md)
- [External dependency and data-egress register](external-dependency-register.md)
- [Available resource and reuse inventory](resource-inventory.md)
- [Branding and compatibility register](branding-compatibility-register.md)
- [Governed workforce request API](workforce-request-api.md)
- [Analyst 360 event and receipt boundary](analyst-event-boundary.md)
- [Durable workforce worker](workforce-worker.md)
- [Workforce maintenance scheduler](workforce-scheduler.md)
- [Workforce reminder delivery](workforce-reminder.md)
- [Private model gateway](model-gateway.md)
- [Private inference fleet](../../infra/aws-inference/README.md)

These documents distinguish three states:

1. **Proven** means the cited implementation and relevant automated tests exist.
2. **Hardening required** means usable implementation exists but a Snowman
   production control is incomplete or unproved.
3. **Vision only** means a schema, UI, or document names a capability without an
   end-to-end production implementation.

No launch document may translate the latter two states into “production-ready.”
