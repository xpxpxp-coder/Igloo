# Snowman workforce maintenance scheduler

Status: implemented and unit-tested in source with hard-dormant AWS service
definitions; PostgreSQL integration, staged recovery, and activation proof remain.

`snowman-workforce-scheduler` is a dedicated maintenance-only process. It owns a
tenant-local service identity with only `workforce.maintenance`; its empty ECS
task role has no Analyst signing key, database grant, model route, object-store
access, shell, or general internet path.

Every 30 seconds it sends a NIP-98-signed, idempotent tick to
`POST /internal/snowman/v1/workforce/maintenance/tick`. The relay rechecks the
service identity and capability in both the authorization and database layers,
then performs one transaction that:

- expires requests and tasks whose deadlines elapsed;
- invalidates leases for expired work;
- requeues expired leases with bounded exponential backoff;
- dead-letters tasks that exhausted their attempt cap;
- expires stale proactive proposals before they can execute;
- appends a correlated request-local hash-chain event for every transition; and
- stores the exact tick result so a lost success response returns the original
  counts instead of starting a second logical tick.

The AWS path uses a separate scheduler security group, private subnets without
public IPs or NAT, split-horizon Route 53 for the exact Snowman hostname, and an
internal TLS ALB. The public Cloudflare-authenticated WAF blocks every
`/internal/` path, so worker/scheduler/integration routes are not exposed through
the public product edge.

Required runtime values are `SNOWMAN_WORKFORCE_RELAY_URL`,
`SNOWMAN_WORKFORCE_SCHEDULER_IDENTITY_ID`, and the separately injected
`SNOWMAN_WORKFORCE_SCHEDULER_NOSTR_PRIVATE_KEY`. The optional interval is bounded
from 1 through 300 seconds; AWS fixes it at 30 seconds.

This scheduler enforces lifecycle safety; it does **not** itself execute queued
proactive actions. The v2 proactive contract materializes supported actions as
ordinary governed work tasks, so identity, model routing, approval, fenced
leases, spend, context, cancellation, completion, and recovery are reused rather
than duplicated. Recurring authorization records are now human-created,
cancellable, tenant/request bound, and hard-limited by cadence/end/occurrence
ceilings, but this maintenance scheduler intentionally cannot claim them. The
separately scoped trigger runtime now claims only schedules bound to its exact
tenant-local identity and submits each occurrence through proactive policy. It
has no task-claim, Analyst, model, AWS signing, or arbitrary tool authority.
The separately scoped `deadline.remind` worker and idempotent in-product
delivery receipt now exist in source. Its isolated AWS service plus staged
lost-response/restart proof remain open. Google Workspace calendar delivery is
a separate optional connector, not a prerequisite for Snowman-local reminders.

## Recurring-work trigger

`snowman-workforce-trigger` signs only private Snowman relay requests. A claim
has a deterministic occurrence/action ID, stable retry by claim ID, and a
two-minute recovery fence. If the process dies before proposal commit, a later
claim reuses the same action ID with a fresh bounded proposal window. If commit
succeeds but the response is lost, the database marks the occurrence submitted
in the proactive insert transaction, preventing a duplicate claim. The AWS
service is separately identified, has an empty task role, a read-only
filesystem, dropped Linux capabilities, no public IP/NAT, and can reach only the
private workforce ingress and required ECR/log/secret endpoints. Desired count
is hard-zero until staged failure tests pass.

After downtime, the trigger materializes at most one overdue occurrence per
schedule and resumes cadence from the observed claim time. It never performs an
unbounded catch-up burst of missed intervals.

A rejected, failed, expired, or dead-lettered occurrence pauses its parent
schedule in the same database trigger chain before request status is refreshed. Cancelling
the request cancels every active or paused schedule and expires unsubmitted
occurrences. There is intentionally no automatic resume after a failed run; a
human must review and authorize a replacement schedule.
