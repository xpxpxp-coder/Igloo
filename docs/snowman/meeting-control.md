# Governed meeting control and mailbox intake

Snowman meeting agents are designed to have real, dedicated Snowman-managed
Google Workspace identities with mailboxes and primary calendars. A user can
forward a conversation to that address or add it to a calendar invitation. This
does not give the meeting model a Gmail credential or unrestricted mailbox
access. A separate Snowman connector retrieves exact Gmail history and Calendar
revisions, stores source content under Analyst 360 evidence/retention authority,
and passes the command center only bounded digest-bound references.

The checked-in `snowman-meeting-control` crate and migration 0048 are the
first executable control-plane foundation for ADR 0006. The separate
[`snowman-meeting-media-gateway`](meeting-media-gateway.md) contract and
migration 0050 now implement the provider-neutral media authority and lifecycle
foundation. They do not activate a provider or claim that Gmail, Calendar,
telephony, speech, or native huddle adapters are deployed.

## Authority split

| Boundary | May decide | Must never accept from email, invitations, speech, or a model |
|---|---|---|
| Google Workspace connector | Exact mailbox registration, Gmail history cursor, Calendar event/revision facts, source digests | Tenant changes, organizer trust, provider approval, consent, arbitrary recipients |
| Analyst 360 | Raw-mail and retained-transcript evidence, immutable artifacts, retention/deletion | Meeting dial authority or direct provider credentials |
| Meeting control | Tenant/workspace admission, schedule revision, consent state, provider/data-class decision, sealed coordinate, session fence | Raw phone/SIP/URL coordinates in a tool call or model-selected route |
| Media gateway | Resolve one sealed coordinate, enforce join window/duration/spend, bridge approved audio route | Unregistered destinations, ambient internet, workforce execution |
| Workforce policy gateway | Admit four bounded meeting intents into normal governed work | Treat meeting content as identity, policy, approval, or capability authority |

## Mail and Calendar flow

1. A dedicated Snowman Google Workspace account receives forwarded mail or an
   invitation. Restricted client workspaces use a distinct account rather than
   a shared mailbox.
2. Gmail Pub/Sub wakes the connector, but notification content is never trusted.
   The connector reads the exact Gmail history changes, maintains a durable
   cursor, renews the watch, and reconciles missed notifications.
3. Calendar sync records provider event and revision digests, recurrence-aware
   times, account attendance state, organizer digest, and a conference-candidate
   digest. Descriptions, attachments, links, quoted mail, and conference text
   remain untrusted Analyst artifacts.
4. Trusted policy must independently approve the organizer, exact tenant,
   accepted event revision, bounded join window, data class, processor route,
   consent requirements, retention, duration, and spend. A forwarded email by
   itself can never schedule or authorize a call.
5. A trusted resolver converts the exact candidate digest into an opaque sealed
   coordinate reference. The reference is stored outside model context and is
   rejected if it resembles a URL, SIP address, phone number, or email address.
6. Schedule/reschedule/cancel operations are digest-idempotent. New Calendar
   revisions must advance monotonically. Cancellation increments the session
   fence and clears participant consent state so a delayed worker cannot join.

## Consent and live execution

Agent disclosure, transcription consent, recording consent, and external
processing consent are separate evidence fields. Calendar acceptance is not
consent. Media starts only for a non-disabled route, inside the join window,
after all currently present participants meet the exact policy. A late joiner
immediately returns the session to `joining` until disclosure and required
consent have been captured. A stale session generation cannot activate or end a
newer attempt.

OpenAI Realtime or ElevenLabs is rejected unless external processing is allowed
for the exact meeting. Restricted content additionally needs digest-bound
restricted-processing approval. Raw audio retention defaults to `none`, and any
retained transcript stays under Analyst evidence authority.

## Model tool boundary

The live model can submit only these untrusted proposals:

- `propose_action_item`
- `clarify_owner`
- `record_decision`
- `request_specialist_work`

The contract has no fields for phone numbers, SIP URIs, conference URLs,
provider selection, credentials, arbitrary recipients, consent, recording,
retention, classification, approval, or capabilities. Each proposal is bound to
the tenant, workspace, meeting, session, generation, service identity, and exact
provider/model turn digest. Accepted specialist work still enters the existing
workforce admission, budget, lease, evidence, and human-gate path.

## Persistence evidence

Migration 0048 defines community-led primary, unique, foreign, and index keys
for dedicated mailbox registrations, untrusted intake receipts, admitted
meetings, idempotent commands, fenced sessions, participant consent, and safe
tool intents. It stores digests and opaque references rather than raw mail,
audio, transcripts, phone numbers, conference URLs, or credentials. Provider
activation is explicitly default-off, and active session rows are impossible
unless activation is enabled and the meeting route is not disabled.

## Remaining work before staged UAT

- Deploy the least-privilege Google Workspace Gmail/Calendar connector with
  Pub/Sub verification, watch renewal, reconciliation, and per-tenant account
  isolation.
- Implement the private meeting-control repository/service transaction layer
  over migration 0048, including row locks and audit receipts.
- Implement the media gateway repository/service plus native huddle, Twilio,
  OpenAI Realtime, and optional output-only ElevenLabs adapters behind the
  checked-in default-off contract; add circuit breakers and exact egress policy.
- Integrate the four safe intents with the workforce policy gateway and the
  post-meeting Command Center thread projection.
- Prove adversarial cross-tenant isolation, spoofed organizers, prompt-injected
  mail/attachments/speech, recurrence and daylight-saving changes, late
  cancellation, consent pause, webhook replay, provider outage, kill switch,
  budget enforcement, recovery, and accessible disclosure in AWS staging.

The dedicated mailbox address, Google OAuth/service-account authorization,
Twilio number/SIP configuration when used, and final tenant activation are
irreducible operator-owned inputs. They are intentionally not prerequisites for
continuing the default-off implementation and test program.
