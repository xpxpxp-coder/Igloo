# Snowman governed agent tool broker

Status: authorization contracts, durable ledgers, least-privilege role checks,
and local policy tests are implemented; no production action execution is
enabled and staged AWS proof remains required.

## Outcome and boundary

The production execution arm does not give an agent a shell, inherited process
environment, URL, provider token, relay private key, AWS credential, arbitrary
MCP server, or general network path. An agent can request only a named,
versioned capability from an operations-owned registry. The private tool broker
rechecks the exact tenant, workspace, request, job, task, agent identity,
service identity, job generation, live lease generation/fence, classification,
minimization evidence, deadline, cancellation/revocation state, and action
digest on every request.

This design supersedes `buzz-dev-mcp` as the production action plane. That MCP
server remains a default-off development surface. Its `workspace.shell`
capability is not a production Snowman capability and cannot be translated into
broker authority.

## Typed routes

The `snowman-tool-broker` crate accepts four closed route families:

- Files are addressed by a registered root ID plus a strict relative path. The
  executor must use a descriptor-relative no-symlink primitive such as Linux
  `openat2` constraints; a string prefix check is not sufficient.
- HTTPS calls use a registered destination ID, method, and resource-template
  ID. Operations owns the host/path mapping. IP literals, caller URLs,
  redirects, ambient proxies, and DNS-selected destinations are prohibited.
- AWS actions use an exact registered account, region, service, operation, and
  resource ID. The trusted broker task role invokes the API; no credential is
  returned to an agent or child process. AWS routes are always critical and
  human-approved.
- Reviewed programs are digest-pinned, invoked directly without a shell, run in
  a fixed offline sandbox, and start from an empty environment. Credential-like
  environment names and program-controlled networking are rejected when the
  registry loads.

The request contains only typed identifiers and content digests. Raw prompts,
files, mail, transcripts, provider payloads, secrets, URLs, phone numbers, or
client data do not enter the Command Center action ledger.

## Dispatch, approval, and evidence

High-impact and critical operations require a live human approval bound to the
exact tenant/workspace/job/task/generation/action digest and bounded by the
action deadline. This supports the sole-founder operating model without
inventing a second internal approver. The broker also reloads the approver's
Snowman workforce session and exact approval capability. Normal high-impact
work may be approved by the founder even when the founder initiated it. A
different approver is required only when operations registers a named,
critical exceptional control with `independent_human`; an unnamed or routine
control cannot silently acquire that requirement. Cancellation that commits
while an action is `authorized` moves it to `cancelled` and prevents dispatch.

The broker must commit `authorized -> indeterminate` immediately before a
side effect. That is the dispatch linearization point. Once indeterminate, a
timeout or lost response is reconciled; it is never automatically replayed.
The UUID action ID plus canonical action digest is the idempotency coordinate.
Exact retries return the existing status/receipt and conflicting reuse is
denied.

Every state change appends a content-free receipt. Receipts form a per-action
hash chain, are signed by a dedicated asymmetric Snowman KMS key, and include
the digest of an immutable external checkpoint. This closes the keyless audit
weakness: database write access alone cannot manufacture a replacement history
with valid signatures and checkpoints. Redacted result and minimization
evidence remain in Analyst 360 under immutable artifact references.

The dedicated database role can read live job/task/lease/identity authority,
insert/update only the action state ledger, read approvals, and append signed
receipts. It cannot delete or truncate action evidence, mutate approval/job
authority, read collaboration events/audit content, use model authority, or use
meeting authority.

## Required runtime sequence

1. Authenticate the purpose-bound job/tool grant over private TLS; the general
   broker job token, model token, and tool token must remain distinct.
2. Lock and reload the exact live authority plus any prior action. Authorize and
   insert `authorized` in one short database transaction.
3. For high/critical work, lock and consume the exact live approval once.
4. Commit `indeterminate` and its signed/checkpointed receipt before the trusted
   adapter invokes any filesystem, HTTPS, AWS, or reviewed-program side effect.
5. Enforce the returned route in a separate sandbox with empty environment,
   no child credentials, no shell, bounded input/output, time/process limits,
   direct-egress denial, and cancellation fencing. HTTPS adapters additionally
   enforce operations-owned destinations and credentials, request/response
   byte caps, connect/total timeouts, no proxy or redirects, resolve-once DNS
   pinning with every private/reserved answer rejected, and a named redaction
   profile.
6. Commit the known terminal outcome and append/sign/checkpoint a redacted
   receipt. Unknown outcomes remain `indeterminate` for reconciliation.

## Remaining activation gates

- Implement the private authenticated HTTP service, task-scoped tool grant,
  transactional PostgreSQL repository, KMS signing, immutable S3 Object Lock or
  equivalent checkpoint, and the four purpose-specific adapters.
- Add an executor-local MCP facade that exposes only capability-registry tools;
  it must never load `buzz-dev-mcp` shell/file mutation in a production image.
- Define exact IAM policies, Snowman-hosted/private destinations, DNS pinning,
  VPC endpoint/security-group routes, root mounts, sandbox profiles, resource
  schemas, rate/cost ceilings, and kill switches in operations configuration.
- Run cross-tenant, stale lease, cancellation race, exact replay, lost response,
  approval revoke/expiry, prompt injection, path traversal, symlink race,
  process-tree escape, proxy/redirect/DNS rebinding/metadata, AWS escalation,
  credential inheritance, log redaction, KMS failure, checkpoint failure,
  backup/restore, and disaster-recovery tests in dormant AWS staging.
- Capture signed image/SBOM/provenance/policy digests and UAT evidence before
  enabling any action capability.

Until those gates pass, all production tool routes remain disabled and this
foundation must not be described as live execution or production-ready.
