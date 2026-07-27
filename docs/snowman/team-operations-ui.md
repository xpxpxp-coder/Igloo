# Snowman AI Workforce command view

Status: feature-flagged, default-off UI foundation. Fixture rendering is limited
to the desktop E2E build. The production adapter is deliberately disabled and
has no start, approve, deny, pause, cancel, or supersede methods.

## What this slice proves

The Agents surface can present one coherent, responsive view of a governed
request and its specialist team without storing raw client material. The view
renders:

- a request and authoritative plan generation, including cancellation and
  supersession posture;
- specialists with distinct Snowman model-route and capability labels;
- dependency-ordered tasks, meeting-derived work, deadlines, progress, and the
  next useful step;
- quiet hours, recurrence, reminders, approvals, and plan/persona/task cost
  ceilings;
- immutable evidence-backed work-product summaries; and
- a resumable Analyst-managed handoff digest for replacement agents.

The TypeScript boundary is strict and bounded. It rejects unknown fields,
cross-snapshot persona/task references, overspent budget projections, and
artifact coordinates that are not content-addressed Analyst 360 references.
No raw mail, transcript, prompt, client row, file URL, provider endpoint,
credential, protocol identifier, or artifact body has a representation in the
view contract.

## Activation and verification gates

The `teamOperations` experiment is off unless a user explicitly enables it.
Even when enabled, the normal desktop build shows an honest “connection off”
state. Fixture data is available only when the E2E build sets
`window.__BUZZ_E2E__.teamOperationsFixture` to `true`; preview controls remain
disabled.

Before replacing the disabled adapter, the live integration must provide a
private, tenant/workspace-scoped read model and separately authenticated,
receipt-returning mutations. It must revalidate workforce identity,
capabilities, live plan/task/lease generations, cancellation, supersession,
approval expiry, evidence authorization, and spend at mutation time. The UI
must never infer authority from a rendered snapshot.

Launch evidence still requires desktop/web/mobile keyboard and screen-reader
testing; 200% zoom and responsive-layout checks; reduced-motion and contrast
verification; live approval/cancellation race tests; expired/superseded snapshot
tests; cross-tenant adversarial tests; lost-response recovery; performance and
bundle-budget checks; and AWS staging UAT against the private orchestration
service. Until those gates pass, this is a production-oriented experience slice,
not a claim that 24/7 autonomous execution is active.
