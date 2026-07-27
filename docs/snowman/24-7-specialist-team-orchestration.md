# Snowman 24/7 specialist-team orchestration boundary

Status: production foundation and bounded private API implemented; activation,
dispatch materialization, worker delivery, completion ingestion, and staged
verification remain gated.

The Snowman orchestration layer turns a governed user request, project,
deadline, recurring analysis, or next-best-action proposal into a bounded
specialist dependency graph. It is a control contract, not another model, tool,
memory, or data service.

## Authority composition

- Analyst 360 remains the authority for governed query execution, raw client
  data, evidence, citations, memory bodies, work products, and handoff
  manifests. The command center accepts only immutable
  `analyst360:sha256:<digest>` references.
- Existing Snowman workforce tasks, approvals, crash leases, and lease
  generations remain the durable queue and fencing authority.
- The existing agent coordinator launches the exact one-shot runtime. The
  existing model gateway and tool broker enforce their own live, generation-
  bound grants, budgets, classification, cancellation, and receipt rules.
- Orchestration receipts contain only those components' immutable identifiers,
  Analyst artifact/evidence references, digests, bounded outcomes, and cost.
  A new agent resumes from the Analyst handoff manifest; the command center
  never stores the raw dataset, mailbox body, transcript, prompt, or work body.

## Specialist team contract

Every persona has a distinct workforce service identity, reviewed persona
digest, exact evaluated model ID/route revision, classification ceiling, exact
tool-capability allowlist, and plan-generation cost ceiling. Every task binds to
one persona, an Analyst-only context-manifest set, exact capability subset,
artifact contract, score evidence, deadline, budget, and an acyclic dependency
set. Client-ready independent review continues to be enforced by the existing
workforce plan kernel.

New personas and plans are disabled/draft by default. Direct provider URLs,
ambient capabilities, raw context, arbitrary tool input, and credentials are
not representable in the contract.

## Useful automatic work

Automatic dispatch occurs only when all of these are true:

1. the exact plan generation is active and not cancelled or superseded;
2. dependency receipts succeeded under the current generation;
3. deadlines and plan/persona/task cost ceilings remain available;
4. the persona and task are enabled, reversible, and do not require approval;
5. confidence and expected-value thresholds pass, risk is below policy, and
   every capability is on the exact automatic allowlist; and
6. tenant-local quiet hours permit the action.

Everything else waits, expires, or requests an exact human approval. Deadline
reminders may bypass quiet hours only when the stored policy explicitly enables
that narrow capability. The live scheduler must resolve local time using the
plan's IANA timezone and persist the timezone database version so DST behavior
is reproducible.

## Cancellation, recovery, and handoff

Plan generations are monotonic. Cancellation or supersession removes live
authority before a new dispatch. The existing workforce lease generation fences
crash recovery; stale worker or provider receipts cannot complete the current
generation. Terminal work-product receipts are unique per plan generation and
task, cost-accounted, and evidence preserving. Sorted receipt metadata produces
a deterministic progress digest and unlocks only DAG nodes whose dependencies
have accepted successful receipts.

## Bounded private service

`snowman-orchestration-service` implements signed, tenant-scoped create-plan,
cancel-plan, and crash-fenced dispatch-claim operations. Plan persistence is
serializable and writes all task rows before dependency edges, so a valid DAG
does not depend on caller ordering. Recurrence records remain disabled by
default. DST gap/fold, weekday, catch-up, and local-minute resolution use the
pinned `chrono-tz/0.10.4` implementation; this is recorded as the compiled
timezone implementation and does not claim an independently attested IANA data
release.

The service does not yet activate a plan, materialize due recurrences into
dispatch rows, deliver coordinator commands, or ingest terminal receipts.
Those absences are fail-closed rather than simulated by the UI.

## Remaining launch gates

- implement activation, recurrence materialization, coordinator delivery,
  terminal-receipt ingestion, and the long-running scheduler loop;
- independently attest the IANA data release used by the pinned timezone build;
- connect the default-off team-operations UI to the private API and complete
  keyboard, screen-reader, zoom, reduced-motion, and mobile verification;
- add crash/lost-response, cancellation race, supersession, duplicate receipt,
  cross-tenant, budget exhaustion, and Analyst-reference authorization tests
  against Postgres/Redis/private AWS staging;
- add dashboards and alerts for overdue tasks, lease churn, approval age,
  scheduler lag, dead letters, cost, and failed handoffs; and
- complete backup/PITR restore drills, dormant-to-active scaling tests, UAT,
  provider failure exercises, and launch-evidence review.

Until those gates pass, this is a production-oriented control foundation, not
a claim that the 24/7 workforce is production active.
