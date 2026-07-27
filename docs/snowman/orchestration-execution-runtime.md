# Governed orchestration execution runtime

The Snowman orchestration worker now has a complete, fixed execution path. It
claims only tenant/workspace-scoped leases from the orchestration API, submits
metadata-only execution projections to the existing agent coordinator, sends
exact cancellation fences to that same coordinator, and publishes only a
locally authored deadline reminder to the Snowman relay.

## Boundaries

- Dispatch carries plan, task, generation, immutable Analyst 360 context
  references, exact capability labels, a minimization digest, cost ceiling, and
  deadline. It cannot carry a user message, prompt body, provider URL, mailbox
  content, transcript, client row, or credential.
- The coordinator resolves the opaque `snowman:model-route:...` reference
  against a reviewed local route profile. The profile fixes runtime, evaluated
  model, specialist role, classification, system policy, and token ceilings.
- The executor prompt is a deterministic reference projection. An executor can
  obtain content only through its separately authorized broker capabilities.
- Cancellation parses the stable `snowman:agent-job:...:generation:...`
  reference and revokes the existing job/token before stopping its exact ECS
  task.
- Reminder delivery uses a separate Nostr key and a fixed Snowman sentence.
  Tenant/workspace work text never enters the event. Stable outbox creation time
  and tags produce the same signed event ID after a lost response.

## Replay and lost-response behavior

Coordinator dispatch and cancellation first claim
`snowman_orchestration_destination_receipts` by tenant and request ID. A changed
body or destination reference conflicts. A completed request returns its exact
stored digest receipt. A crash while `processing` safely repeats the same
idempotent coordinator operation. The coordinator's job ID and launch client
token remain stable, while cancellation is terminal and repeatable.
Generated dispatch/outbox coordinates are composite foreign keys to the exact
tenant and workspace authority rows, and the coordinator rechecks that scope
before every claim; orphaned or cross-workspace coordinates cannot be inserted.

Reminder retry republishes the same signed Nostr event. Relay duplicate handling
returns the same accepted event ID, so a network loss cannot create a second
reminder.

## AWS posture

`infra/aws/orchestration_runtime.tf` packages the API and per-tenant workers as
non-root, read-only Fargate tasks with `desired_count = 0`. The only network
routes are private Snowman orchestration/coordinator/relay endpoints, RDS for
the API, AWS interface endpoints, and VPC DNS. There is no NAT, public IP,
provider route, task role, or ECS Exec. Private TLS ingress is separately
default-off and requires the exact Snowman hostname and local ACM certificate.

## Activation evidence

Do not raise desired count until all of the following pass in staging:

1. migration 0059 and the coordinator least-privilege role verification;
2. cross-tenant dispatch/cancel/replay tests against PostgreSQL;
3. lost-response injection before and after coordinator acceptance;
4. duplicate reminder publication proving one stable event ID;
5. cancellation during launch and during active execution;
6. private DNS/TLS and security-group reachability tests with public egress
   denied; and
7. cost, dead-letter, scheduler-lag, and task-health alarms in launch evidence.
