# Governed live meeting media gateway

Status: **executable control contract and persistence schema; provider network
adapters are not activated or staging-proven**.

The `snowman-meeting-media-gateway` crate and migration 0050 define the media
boundary between the consent-complete meeting-control service, native Snowman
huddles, and explicitly approved phone/speech providers. They do not place a
call, connect a WebSocket, resolve a conference coordinate, or claim a live
Twilio/OpenAI/ElevenLabs integration.

## Authority and data boundary

Media authority can only be derived from a `ScheduledMeeting` whose status is
already `active`. This makes the meeting-control participant disclosure and
consent checks a type-level prerequisite. The resulting grant binds the exact
tenant, workspace, meeting, mailbox identity, meeting-agent identity, Calendar
event revision, schedule revision, session ID and generation, conference
approval, sealed coordinate, classification, processor routes, retention,
duration, cost, admission evidence, and consent evidence.

A join command contains no URL, phone number, SIP URI, provider session ID,
provider credential, prompt, or recipient. A trusted provider adapter receives
the opaque sealed coordinate only after all gateway policy checks pass. Email,
Calendar descriptions, attachments, DTMF, spoken instructions, transcripts,
and model output cannot replace that seal or choose a provider route.

Raw audio is represented by a borrowed, non-serializable
`TransientAudioFrame`. The persistable receipt contains only byte count,
sequence, time, and SHA-256 digest. Migration 0050 prohibits raw-audio
retention. Any retained transcript is referenced only as an immutable
Analyst 360 artifact; transcript text does not enter Command Center tables.

## Provider-neutral lifecycle

Every operations registration defaults to disabled. Enabling a route requires
an exact tenant/workspace/mailbox/gateway-service binding, provider account or
project digest, explicit provider allowlist, per-session duration and spend
ceilings, concurrency ceiling, and policy evidence.

The reference state machine implements:

- digest-idempotent join and stop commands;
- exact session-generation fencing and newer-cancellation wins;
- provider-establishment binding to the registered provider account/project;
- exact-once provider usage receipts and immediate teardown on cost overage;
- deadline/duration kill switches independent of provider callbacks;
- authenticated callback abstraction over exact raw URL/body/headers, bounded
  callback age, and delivery-ID replay fencing;
- an output-only ElevenLabs request that accepts only approved bounded response
  text and operations-catalog voice/model IDs;
- acceptance of meeting model output only through the four bounded
  meeting-control intents. Audio content never becomes execution authority.

## Current provider contracts

### Native Snowman huddles

The native adapter must bridge only the admitted Snowman huddle seal and exact
session generation through private Snowman infrastructure. It must not fall
back to a public Nostr relay, Block endpoint, arbitrary WebSocket origin, or
model-supplied URL.

### Twilio telephony

The primary phone adapter is a dedicated Snowman Twilio account/subaccount.
[Twilio Media Streams](https://www.twilio.com/docs/voice/media-streams) supports
bidirectional audio using one WebSocket per call; the gateway therefore treats
the WebSocket and call as one fenced provider session. Twilio documents that
bidirectional output is `audio/x-mulaw` at 8 kHz, buffered in order, with
`mark`/`clear` controls in its
[WebSocket message reference](https://www.twilio.com/docs/voice/media-streams/websocket-messages).

The public edge must validate the lowercase `x-twilio-signature` for Media
Stream upgrades and `X-Twilio-Signature` for HTTP callbacks using Twilio's
supported request-validation library, the exact externally visible URL, and
the original parameters or raw JSON body. Twilio warns that callback parameters
can be added over time, so adapters must not validate a hard-coded subset; see
[Twilio webhook security](https://www.twilio.com/docs/usage/webhooks/webhooks-security).
Phone/SIP coordinates stay inside the sealed-coordinate resolver. Outbound
dialing is limited to a pre-approved Calendar coordinate; there is no arbitrary
dial tool. Recording is off, provider data retention must be configured to the
approved minimum, and account/subaccount fraud and spend limits remain required.

### OpenAI Realtime

For server media such as a call system, OpenAI recommends a server-to-server
WebSocket to `/v1/realtime`, with a server-held API key and a privacy-preserving
`OpenAI-Safety-Identifier`; see the official
[Realtime WebSocket guide](https://developers.openai.com/api/docs/guides/realtime-websocket).
Direct OpenAI SIP is not the default Snowman topology because it would point the
carrier leg at an external provider coordinate. If separately approved, the
official [Realtime SIP flow](https://developers.openai.com/api/docs/guides/realtime-sip)
uses a signed `realtime.call.incoming` webhook, a server-side accept/reject
decision, and a sideband WebSocket keyed by the exact `call_id`.

Only the trusted Snowman server maintains tools and business logic. The
[server-side controls guide](https://developers.openai.com/api/docs/guides/realtime-server-controls)
documents that sideband pattern. `response.done` usage receipts, explicit
duration/token ceilings, and a Snowman kill switch are mandatory because
Realtime cost grows with conversation context; see
[OpenAI's Realtime cost guide](https://developers.openai.com/api/docs/guides/realtime-costs).

### ElevenLabs output renderer

ElevenLabs is optional and output-only. It receives approved response text,
never inbound audio, raw transcript, Analyst evidence, provider coordinates, or
tool context. Its current API supports scope restrictions, credit quotas, and
IP allowlisting on keys; see
[ElevenLabs API authentication](https://elevenlabs.io/docs/api-reference/authentication).
Streaming TTS uses the documented
[text-to-speech WebSocket](https://elevenlabs.io/docs/api-reference/text-to-speech/v-1-text-to-speech-voice-id-stream-input).
The deployed adapter must use an operations-catalog voice/model, a restricted
server-side key, exact egress, an independent cost ceiling, and immediate
cancel/clear behavior.

## Persistence

Migration 0050 adds tenant-leading keys for disabled route registrations,
fenced media sessions, append-only command receipts, authenticated callback
receipts, provider usage receipts, and digest-only turn receipts. It has no
column capable of storing a raw target, provider credential, audio payload, or
transcript body. A dedicated media-gateway database identity still needs to be
provisioned before deployment; the general relay and meeting model must not
receive these write privileges.

## Activation gates

Before any route can be called production-ready:

1. Implement and review the private repository/service transaction layer over
   migration 0050 with row locking, append-only audit receipts, and a dedicated
   least-privilege database role.
2. Implement native huddle and Twilio adapters behind private Snowman services;
   implement OpenAI Realtime and ElevenLabs only for classifications and tenants
   whose external-processing policy explicitly permits them.
3. Store provider secrets in purpose-specific AWS Secrets Manager entries;
   enforce exact DNS/TLS egress, no ambient proxy, WAF/rate limits on public
   callback edges, secret rotation, and provider account/project binding.
4. Prove spoofed signature, stale callback, exact-retry, changed-body replay,
   wrong-tenant/session/revision/fence, late cancellation, late participant,
   provider outage, reconnection, out-of-order audio, arbitrary dial attempt,
   prompt-injected speech, cost overage, duration expiry, and kill-switch tests.
5. Prove raw audio is absent from database, logs, traces, crash dumps, and S3;
   prove retained transcript references resolve only through Analyst 360
   authorization and retention.
6. Complete disclosure/consent, telephony, native huddle, accessibility,
   latency, quality, cost, backup/recovery, and operator-runbook UAT in dormant
   AWS staging before tenant activation.

Provider credentials, Snowman Twilio number/subaccount and approved SIP setup,
OpenAI project/API authorization, optional ElevenLabs restricted key and voice,
and final route activation acceptance are operator-owned inputs. They do not
block completing or testing the default-off adapters.
