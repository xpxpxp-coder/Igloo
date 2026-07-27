# Snowman 360 production activation inputs

Status: source implementation and dormant packaging in progress. This register
separates technical work Snowman can automate from the few actions that require
the sole founder's external account, inbox, or business authority.

## Operating rule

Source construction, tests, evidence capture, infrastructure plans, security
policy, recovery automation, and dormant staging deployment are technical work.
They do not require routine founder approval. Production traffic, external
commitments, provider consent, and acceptance of residual risk remain explicit
human gates.

No Block-operated endpoint, image, update service, telemetry destination, relay,
storage service, or credential is an approved Snowman production dependency.
Compatibility protocol names may remain in source or on the wire when changing
them would break interoperability; they grant no network authority.

## Inputs needed from the founder

| When | Input | Exact purpose | Safe default until supplied |
| --- | --- | --- | --- |
| Now, to resume cloud inventory and plans | Renew the `snowman360-management-admin`, `snowman360-staging-application-deployer`, and `snowman360-staging-bootstrap` AWS IAM Identity Center sessions | Read current state, restore protected inputs through their governed path, produce exact plans, and later deploy dormant workloads | No AWS mutation; all desired counts stay zero |
| Before monitored staging | Confirm the Snowman security SNS email subscription or select an already monitored Snowman-owned alert consumer | Prove real delivery, failure, and redrive of operational/security alerts | Activation gate remains closed |
| Before mailbox/calendar UAT | Provision licensed Google Workspace users for the general meeting agent and each restricted client boundary, including Aptive; grant only the reviewed Gmail and Calendar scopes | Receive forwarded mail/invites, maintain a primary calendar, and join only governed meetings | Mail/calendar intake remains disabled |
| Before voice/provider UAT | Put Snowman-owned Twilio and OpenAI credentials into the exact Secrets Manager paths and configure approved phone numbers/provider projects; optionally do the same for ElevenLabs output-only TTS | Exercise phone, realtime voice, and optional premium speech output through the Snowman provider boundary | All provider egress and meeting media stay disabled |
| Before client-data UAT | Confirm the exact Aptive release/data-owner decisions already recorded by Analyst 360 | Permit governed Analyst evidence/query paths to use the approved release | No raw Aptive data reaches Command Center or agent runtimes |
| After staged evidence is complete | Perform the founder-operated UAT journeys and record final activation acceptance | Establish real usability and residual-risk acceptance; tests cannot manufacture this evidence | Production traffic stays disabled |

Provider console actions should create or rotate credentials only. Secret values
must never be pasted into chat, source control, Terraform variables, task
overrides, logs, or launch-evidence documents.

## Inputs that are not required from the founder

- Choosing ordinary implementation details, libraries, schemas, queues,
  retry policies, health checks, or AWS resource shapes.
- Repeating product context or approving each code change.
- Creating fictional additional employees, approvers, or on-call rotations.
- Supplying raw Aptive rows, full mailbox contents, transcripts, provider
  credentials, or production database credentials to Command Center agents.
- Approving OpenClaw or Hermes as an authority. The native ACP harness is the
  execution interface; any additional runtime is an optional, pinned,
  sandboxed adapter under the same Snowman grants and receipts.

## Approved ecosystem boundary

AWS, Google Workspace/Google Cloud, Cloudflare, Snowman GitHub/container
custody, Twilio, OpenAI, and an explicitly enabled ElevenLabs route are approved
integration families. Approval means Snowman may build a least-privilege,
audited connection; it does not make provider processing equivalent to local
Snowman storage.

Meeting audio, email, and invitations can themselves contain personal or client
information. Therefore the system cannot truthfully guarantee that a live voice
provider sees no PII merely because Analyst 360 withholds raw client datasets.
Restricted/Aptive meetings default to the Snowman/AWS route. OpenAI Realtime,
Twilio media, or ElevenLabs is enabled only for an allowed classification and
consent policy, with bounded transient payloads, no raw Command Center
persistence, exact egress destinations, and immutable digest receipts.

## Activation order

1. Renew read/plan identities and restore protected staging inputs without
   guessing values.
2. Publish immutable source and signed/SBOM-attested images.
3. Apply only dormant private staging infrastructure and verify desired count
   zero, blocked public edge, least-privilege roles, backups, logs, and alarms.
4. Confirm alert delivery and provision the exact Workspace/provider identities
   and secret references.
5. Activate one staging capability at a time; run tenant-isolation, recovery,
   provider-failure, accessibility, mobile, meeting, and 24/7 orchestration UAT.
6. Assemble the immutable launch bundle and obtain final founder acceptance.
7. Promote the same verified image/configuration and enable production traffic
   through the recorded activation gate.

