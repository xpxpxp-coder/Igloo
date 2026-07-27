# ADR 0006: Governed live meeting and huddle agent

- Status: Accepted for default-off implementation
- Date: 2026-07-26
- Decision owner: Snowman AI sole-founder operator

## Outcome

Snowman Command Center will support a visibly identified AI meeting participant
that can join a native huddle or an authorized phone meeting, converse in real
time, capture decisions and action items, create a durable Command Center
thread, and dispatch scoped follow-up work through the governed Snowman
workforce. It is a meeting interface to the existing workforce, not a second
orchestration or authorization plane.

Igloo already has authenticated huddle lifecycle events and an Opus audio path
at `/huddle/{channel_id}/audio`, including cross-pod ownership/fencing. The
meeting participant therefore joins as a tenant-bound Snowman service identity
through the existing huddle protocol. A separate meeting-media gateway performs
bounded Opus/PCM conversion and is the only component permitted to reach an
approved speech provider. Browser, desktop, mobile, relay, and specialist agents
never receive provider credentials or arbitrary media destinations.

For phone meetings, a Snowman-owned Twilio account may provide narrowly scoped
PSTN/SIP ingress and outbound dialing. Dial targets, conference identifiers,
DTMF steps, time windows, caller IDs, and maximum duration come from an
approved meeting object; neither a model nor meeting content may choose an
arbitrary number or SIP URI. Webhooks require signature, timestamp, replay,
tenant, and exact Snowman-host validation. Recording is disabled by default.
Twilio documents bidirectional Media Streams as a WebSocket bridge that can
receive call audio and return generated audio:
<https://www.twilio.com/docs/voice/media-streams>. AWS Chime SDK remains the
Snowman-ecosystem alternative and supports outbound calls through a SIP media
application:
<https://docs.aws.amazon.com/chime-sdk/latest/dg/use-create-call-api.html>.

## Voice routes

1. **Snowman/AWS route (default for restricted and Aptive work).** Audio and
   intermediate text remain in Snowman-controlled AWS services or Snowman-hosted
   models. This is the only route compatible with the current zero-third-party
   processing default.
2. **OpenAI Realtime route (optional).** OpenAI's Realtime API supports
   low-latency speech sessions over WebRTC, WebSocket, and SIP, along with
   interruption handling and function calls. Snowman uses a server-side
   WebSocket/sideband controller so tools and business logic remain in the
   Snowman gateway. This route is disabled unless the workspace and meeting
   classification permit OpenAI to process live audio. Direct speech-to-speech
   cannot guarantee that unexpected PII is redacted before the provider hears
   it.
3. **ElevenLabs output route (optional, not the default).** ElevenLabs may be
   used only as a premium text-to-speech renderer in a chained voice flow. It
   receives approved response text, not inbound meeting audio, raw transcripts,
   evidence packets, or workforce credentials. It is not inserted into the
   OpenAI speech-to-speech path because that would add latency, cost, and another
  processor without improving orchestration.

ElevenLabs documents its streaming TTS interface here:
<https://elevenlabs.io/docs/eleven-api/guides/how-to/text-to-speech/streaming>.

OpenAI documents Realtime speech-to-speech as the low-latency route with
barge-in, turn taking, tools, and handoffs, while its chained voice architecture
is the better fit when transcripts and policy checks must be explicit between
stages: <https://developers.openai.com/api/docs/guides/voice-agents>. OpenAI also
documents server-side sideband control for WebRTC and SIP sessions:
<https://developers.openai.com/api/docs/guides/realtime-server-controls>. Its SIP
surface supports inbound-call webhooks, accept/reject, monitoring, transfer,
and hangup: <https://developers.openai.com/api/docs/guides/realtime-sip>.

## Meeting-to-workforce contract

- Every meeting has an exact tenant, workspace, parent thread, classification,
  participant roster, consent state, provider route, budget, deadline, and
  retention policy.
- The AI participant announces itself audibly and visually. Transcription,
  recording, and external processing are separate consent flags. A participant
  joining late receives the disclosure before their audio is processed.
- Incoming speech is untrusted content. It can propose a decision or task but
  cannot change identity, routing, retention, provider, capabilities, approval,
  or destination policy.
- During the call, the realtime model receives only meeting-scoped tools such as
  `propose_action_item`, `clarify_owner`, `record_decision`, and
  `request_specialist_work`. Tool calls enter a Snowman policy gateway; they do
  not execute shell, network, deployment, billing, export, identity, or client
  data actions directly.
- Approved safe actions create idempotent workforce requests through the same
  coordinator, leases, model grants, budgets, evidence chain, and specialist
  review used by non-voice work. High-impact or externally consequential work
  remains human-gated.
- Raw audio is not retained by default. Raw or speaker-attributed transcripts,
  when expressly enabled, remain under Analyst 360 evidence authority. Command
  Center receives bounded rolling summaries, decisions, action items, citations,
  and immutable Analyst artifact references—not raw Aptive transcripts.
- The post-meeting thread contains attendance/consent evidence, a concise
  summary, decisions, open questions, owners, deadlines, dispatched task status,
  and links to resulting work products. New agents rebuild context from that
  governed packet rather than replaying unbounded audio.

## Required controls and evidence

- Distinct service identity and short-lived credential per meeting agent;
  revocation and hangup must stop media, tools, and downstream work.
- Exact provider host allowlists and per-route network policy; provider keys in
  Snowman Secrets Manager only; no Block or ambient internet route.
- Tenant isolation across audio rooms, provider sessions, transcripts, tool
  calls, threads, artifacts, logs, metrics, retries, and caches.
- Bounded audio buffers, silence/meeting duration limits, concurrency and spend
  ceilings, provider circuit breakers, backpressure, reconnect fencing, and
  duplicate-webhook/call protection.
- Consent and recording-law configuration by meeting jurisdiction, with a
  fail-closed route when policy is unknown. Snowman does not infer consent from
  calendar invitation or dial-in access alone.
- Evaluation for interruption, diarization/owner attribution, action-item
  precision/recall, false task creation, hallucinated commitments, prompt
  injection spoken aloud, sensitive-data leakage, latency, recovery, and
  accessibility.

This feature is not production-ready until those controls pass staged huddle
and phone UAT. Twilio, OpenAI, and ElevenLabs authorization for design does not
activate them for any tenant or data class by default.
