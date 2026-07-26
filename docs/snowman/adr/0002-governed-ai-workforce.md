# ADR 0002: Build a governed, durable Snowman AI Workforce

- Status: Accepted
- Date: 2026-07-25
- Decision owner: Snowman AI sole-founder operator

## Context

Snowman 360 must feel like an always-available expert team, not a collection of
independent chat sessions. A user request may require research, governed
analytics, planning, production, and independent review. Different roles may
perform best with different models and tools. Work must continue safely when a
desktop is offline, preserve enough context for a replacement agent, anticipate
useful next steps, and produce client-ready artifacts without expanding the
Aptive or tenant data boundary.

Igloo already provides valuable primitives: teams and personas, per-agent model
and runtime configuration, signed collaboration events, team snapshots, nests,
workflows, schedules, reminders, agent observation, and persistent coordination.
Those primitives materially accelerate the product, but local agent processes
and free-form prompts are not a durable governed workforce.

## Decision

Build the Snowman AI Workforce as three cooperating planes:

1. The Snowman Command Center accepts objectives, shows the team, plan, work,
   approvals, artifacts, deadlines, evidence, cost, status, and next-best steps.
2. A durable AWS orchestration plane decomposes work, selects specialist roles,
   leases tasks to tenant-bound workers, schedules proactive work, enforces
   budgets/capabilities/approvals, handles retries and cancellation, and records
   correlated receipts.
3. Analyst 360 remains the governed intelligence, evidence, memory, decision,
   and Aptive data authority. It returns bounded context packets, evidence
   manifests, lifecycle events, and immutable artifact references through the
   versioned integration gateway.

Every agent instance has one role, one tenant/workspace service identity, an
explicit capability set, a model route allowed for the data class, bounded input
context, expected artifact contract, cost/deadline budget, and revocation state.
The orchestrator can delegate and parallelize work, but capabilities never
increase through delegation.

Model selection is policy-constrained optimization. Agents and clients call only
`models.snowmanai.org`; they never receive model-vendor credentials or direct
vendor endpoints. Strict mode uses models hosted in Snowman AWS. Any future
external model processor requires an explicit provider/data-class decision and
still remains behind the Snowman gateway.

Memory is not a transcript dump. Handoffs use versioned, content-addressed
context packets containing objective, constraints, decisions, open questions,
work graph, artifact/evidence references, provenance, freshness, classification,
and next useful actions. Raw Aptive rows, unrestricted query results, secrets,
and unbounded transcripts do not enter Command Center memory.

Proactivity requires authority. An automatic action must trace to an approved
objective, schedule, signal, or policy and be reversible and low risk, or stop
for an expiring human approval. The system may automatically monitor deadlines,
refresh approved analytics, prepare drafts, run checks, organize context, and
recommend or execute safe next steps. Destructive, privileged, externally
binding, client-data-exporting, identity, billing, deployment, and other
high-impact actions retain human gates.

## Quality and evidence

A lead agent is responsible for orchestration and synthesis. Specialist outputs
must satisfy artifact-specific contracts. A separate quality/risk reviewer checks
factual support, citations, completeness, contradictions, data classification,
accessibility, presentation, and client readiness before publication. Human
review is used for policy gates and judgment that cannot be safely automated,
not as a substitute for technical verification.

## Consequences

- Igloo remains the acceleration substrate, while AWS durability and governance
  are explicit additions rather than overstated existing capabilities.
- Users can configure role-specific models without granting agents arbitrary
  provider egress or credentials.
- New agents can resume useful work from bounded context and evidence rather
  than replaying entire conversations.
- 24/7 work requires an AWS service, operational SLOs, recovery, and spend
  controls; a running desktop is not part of the production availability model.
- “Next best action” remains useful and proactive without becoming unbounded
  autonomous authority.

## Implemented foundation

The `snowman-workforce` policy kernel now validates bounded, acyclic specialist
plans; requires explicit tenant service identities, capabilities, context
digests, artifact contracts, budgets, risk, reversibility, and approval posture;
selects the strongest policy-approved per-role model (or validates a configured
override) behind Snowman DNS; and requires a separately identified downstream
quality/risk reviewer for client-ready delivery. Its proactive policy executes
only useful, confident, low-risk, reversible, allowlisted work below a hard cost
threshold and turns other useful work into an approval request.

The `buzz-db` workforce store now adds durable request/task state reconciliation,
fenced leases and recovery, exact-snapshot approvals, hard spend/token ledgers,
an evaluated tenant model catalog, atomic lead-to-specialist DAG expansion,
dependency readiness, task-level ceilings, immutable context coordinates, and a
tenant-serialized, domain-separated lifecycle-event hash chain that rejects
credential-like payload fields. The private plan endpoint rehydrates request
authority server-side and never accepts a caller-supplied gateway. These are
source foundations, not a claim that the AWS scheduler, workers, sandbox, model
gateway, or external KMS checkpoints have passed staging.

The human control path can now cancel a request idempotently under exact
tenant/capability authority. Cancellation atomically marks every non-terminal
task, destroys all live leases, and appends bounded human-attributed evidence,
so an already-running worker loses heartbeat, spend, and completion authority as
soon as the transaction commits.

Human task decisions are also an enforceable control path rather than a UI-only
record. Approve, deny, and revoke operations bind to the immutable task snapshot
and a maximum 24-hour expiry, use exact replay protection, append hash-chain
evidence, and invalidate any live lease immediately on denial or revocation.
