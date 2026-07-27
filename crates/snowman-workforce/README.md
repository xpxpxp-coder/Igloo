# Snowman AI Workforce policy kernel

This crate is the deterministic governance layer between an orchestrator's
proposed specialist team and the durable Snowman task queue. It does not call a
model or execute a tool.

It enforces:

- explicit tenant-bound service identity, capabilities, budgets, artifact type,
  context references, dependencies, risk, reversibility, and approval posture
  for every specialist task;
- best-fit or explicitly configured per-agent model selection only from the
  classification-approved Snowman model catalog;
- Snowman-controlled gateway destinations, bounded context/token/cost totals,
  and rejection of direct model providers and ambient wildcard capabilities;
- acyclic task graphs and a separately identified quality/risk reviewer after
  all producer tasks for client-ready delivery; and
- bounded, classified, content-addressed handoff manifests that let replacement
  agents resume from evidence, decisions, open-question digests, and governed
  next actions without copying raw datasets or transcripts; and
- automatic proactive execution only for useful, confident, low-risk,
  reversible, allowlisted actions below the hard cost ceiling. Other useful
  actions stop at human approval; prohibited or ungrounded actions are rejected.

The AWS worker will persist the governed plan through `buzz-db` fenced leases
and will emit hash-chained lifecycle receipts. Model evaluation data and tenant
policy remain controlled configuration; the crate never silently expands an
agent's scope to obtain a result.
