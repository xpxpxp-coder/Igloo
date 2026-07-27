# Snowman Command Center governance

Snowman AI currently uses a sole-founder operating model. The founder is the
accountable product owner, security owner, release authority, and incident
commander. Automation supplies independent, reproducible evidence; it does not
invent employees, committees, or approvals that do not exist.

## Change control

- Every production change is tied to an immutable commit SHA.
- Local and hosted checks run before `main` advances.
- A separate AI review pass records actionable findings; all P0/P1 findings are
  resolved before promotion.
- Direct `main` updates are fast-forward only and use the exact reviewed SHA.
- Production activation is distinct from code promotion and remains explicitly
  accepted by the founder.

## Separation and independent review

Where an external independent reviewer is legally or contractually required,
Snowman engages one and preserves their evidence. Otherwise, preventive cloud
controls, least-privilege roles, immutable logs, automated policy checks, and
post-change review provide practical separation for a one-person company.

## Security and data authority

Analyst 360 remains authoritative for governed data access, evidence, memory,
recommendations, decisions, outcomes, and Aptive client data. Snowman Command
Center receives only tenant-scoped commands, statuses, citations, manifests,
and immutable artifact references. It does not share Analyst 360 databases,
caches, or object stores and does not receive raw client data by default.

Security concerns are reported to **security@snowmanai.org**. See
[SECURITY.md](SECURITY.md) and the production acceptance records under
`docs/production/` for control details and evidence.
