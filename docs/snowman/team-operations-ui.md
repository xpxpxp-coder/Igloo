# Snowman AI Workforce command view

Status: feature-flagged, default-off governed integration. Fixture rendering is
limited to the desktop E2E build. Production builds connect only when both
`VITE_SNOWMAN_ORCHESTRATION_ORIGIN` and `VITE_SNOWMAN_WORKSPACE_ID` identify an
exact Snowman HTTPS service and UUID workspace; otherwise the experience fails
closed without exposing mutation methods.

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

## Live connection and authority

The `teamOperations` experiment is off unless a user explicitly enables it.
When configured, the desktop signs a fresh NIP-98 event for each exact request
URL/body. The orchestration service GET projection is admitted only for a live
human device session that has `workforce.requests.read` and an explicit active
caller row for the tenant/workspace. It returns bounded plan, specialist, DAG,
schedule, budget, reminder, immutable work-product receipt, and lifecycle
receipt metadata; it has no raw objective, prompt, context body, mail,
transcript, client row, provider endpoint, or credential field.

Activate, pause, cancel, and supersede controls are enabled only when the live
projection carries the exact capability and its current plan state permits the
transition. The adapter binds the signed command body and returned receipt to
tenant, workspace, plan, and generation before refreshing. Task approve/deny
continues to use the existing workforce API and binds to the published task
snapshot digest; the UI does not invent a second approval authority. New user
requests enter through the existing workforce request API, after which the
governed planner creates the plan. Request text is held only in transient form
state and is not added to the command-center projection.

Fixture data is available only when the E2E build sets
`window.__BUZZ_E2E__.teamOperationsFixture` to `true`; preview controls remain
disabled.

The deployment must provision a caller admission for each human/workspace and
retain the default-off build variables until private routing, workforce
enrollment, and capability grants are verified. Rendering never grants
authority: every server mutation revalidates the live identity, session,
capability, policy generation, plan generation, cancellation/supersession
fences, and receipt replay state.

Launch evidence still requires desktop/web/mobile keyboard and screen-reader
testing; 200% zoom and responsive-layout checks; reduced-motion and contrast
verification; live approval/cancellation race tests; expired/superseded snapshot
tests; cross-tenant adversarial tests; lost-response recovery; performance and
bundle-budget checks; and AWS staging UAT against the private orchestration
service. Until those gates pass, this is a production-oriented experience slice,
not a claim that 24/7 autonomous execution is active.
