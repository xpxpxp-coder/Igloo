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
