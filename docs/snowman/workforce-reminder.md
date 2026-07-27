# Snowman workforce reminder delivery

`snowman-workforce-reminder` is an identity-isolated local delivery worker for
the exact `deadline_operations` / `deadline.remind` capability. It is not a
general messaging agent. It has a Snowman relay key and private HTTPS route,
but no Analyst 360 credential, model-provider credential, AWS signing key,
filesystem tool, arbitrary message body, or recipient parameter.

Every reminder remains inside the Snowman Command Center. A human authorizes a
bounded recurring schedule; the recurring trigger submits the occurrence
through proactive policy; the ordinary task queue applies model-route,
capability, approval, lease, retry, cancellation, and dead-letter controls; and
the reminder worker presents only its fenced lease and deterministic delivery
ID to the private relay endpoint.

The relay derives the recipient from the original request's live Snowman human
identity and active device bindings. It fixes the content to
`Snowman work is ready for your review.`, adds only request/task/delivery
coordinates, signs kind `40007` with the Snowman relay identity, stores it in
the tenant partition, and returns a content-addressed receipt. Raw objectives,
Aptive rows, transcripts, artifact bodies, email addresses, and user-supplied
notification text are never placed in the reminder event.

The first authorized attempt snapshots at most 16 active device keys in
`snowman_work_reminder_receipts`. A lost response, lease recovery, or retry
therefore reconstructs the same signed event instead of duplicating or
retargeting it. Revoked, expired, suspended, cross-tenant, or absent human
sessions fail closed; the durable task can retry under the ordinary recovery
policy when a live device binding exists.

This source implementation is not staged proof. AWS source now defines a
separate empty task role, exact secret, security group, hard-dormant service,
and private-route policy. Image deployment, identity/grant bootstrap, alarms,
and restart/lost-response tests remain required before activation.
Google Workspace email/calendar delivery is a separate optional connector and
is not required for the in-product reminder path.

## Activation contract

The reminder service identity receives exactly `workforce.tasks.execute` and
`deadline.remind`; it does not receive `workforce.context.write`. Its tenant
model catalog entry uses the `deadline_operations` role as a deterministic
local-operation route—no inference call is made. Automatic execution remains
off until the relay is configured with `deadline.remind` in
`SNOWMAN_PROACTIVE_AUTOMATIC_CAPABILITIES`, a positive hard automatic-cost
ceiling, and the reviewed confidence threshold. Otherwise the ordinary
proactive decision creates an expiring human approval gate.

Terraform activation requires a distinct `reminder_profiles` identity, matching
`reminder_desired_count`, an exact private Snowman relay URL, and the
out-of-band secret field `SNOWMAN_WORKFORCE_REMINDER_NOSTR_PRIVATE_KEY`. The
checked-in task definition enforces desired count zero until a reviewed staging
override proves identity revocation, no-active-device behavior, lost-response
replay, cross-tenant denial, live/persisted notification delivery, and restart
recovery.
