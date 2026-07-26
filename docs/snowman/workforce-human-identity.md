# Snowman workforce human identity bridge

Status: enrollment contract and least-privilege AWS key boundary implemented in
source; production activation remains blocked on revocation/logout, client UX,
live private routing, current Google Workspace MFA-policy evidence, and staged
adversarial proof.

## Decision

Analyst 360's existing Google Workspace OIDC boundary is the initial Snowman
identity authority. It issues one-time, body-bound AWS KMS assertions to the
separate Command Center. This reuses the hardened Snowman sign-in path without
sharing a database, session store, token, or client-data authority.

The Command Center remains the authority for its tenant-local identity, role,
capabilities, device session, and Nostr signature enforcement. Nostr is the
device cryptographic layer, not the workforce identity or authorization layer.

## Enrollment flow

1. A user authenticates through the Snowman Google Workspace application and
   receives an Analyst 360 session.
2. The client creates a fresh kind `24243` Nostr device-possession proof bound
   to the one-time assertion UUID, broker, Command Center community, and purpose
   `snowman-workforce-session-enrollment`.
3. Analyst 360 revalidates the live session, active linked Google identity,
   exact Aptive client/project scope, role, hosted domain, and authentication
   age. Authentication must be no more than ten minutes old.
4. Analyst 360 derives a broker- and community-domain-separated pseudonymous
   SHA-256 subject binding and signs the canonical request/body digest with its
   dedicated asymmetric AWS KMS key.
5. The private Command Center endpoint derives the tenant from the configured
   host, verifies the exact broker/scope/key binding, a 90-second assertion
   lifetime, current MFA-policy evidence, the KMS signature, and the Nostr
   signature and purpose tags.
6. In one database transaction the receiver consumes the assertion, creates or
   rotates the device session, assigns receiver-owned capabilities, reconciles
   relay membership, and writes an enrollment receipt. Reuse fails closed.

Source roles map downward as follows: Analyst `admin` becomes Command Center
`owner`, `reviewer` becomes `admin`, and `analyst` or `viewer` becomes `member`.
Owners/admins may create, read, and cancel workforce requests, approve tasks,
and manage schedules. Members may create and read requests. No role inherits
all relay scopes from key possession.

## Data-minimization boundary

The enrollment request may contain only the broker and tenant scope, a bounded
display name without an email address, the Analyst source role, authentication
time, the pseudonymous provider-subject digest, and the public Nostr proof.

The following never cross into Command Center or its stores:

- Google ID, access, or refresh tokens;
- email addresses or the raw Google subject;
- Analyst session tokens or cookies;
- Aptive rows, extracts, transcripts, prompts, answers, or work products; and
- model-provider credentials.

Audit entries explicitly record those exclusions. The Command Center receipt
also reports `provider_token_persisted=false`, and Analyst rejects any receipt
whose exact field set, identity derivation, device key, or mapped role differs.

## AWS isolation

The Analyst workload account creates a dedicated RSA-3072 `SIGN_VERIFY` KMS key.
Its web task role receives only `kms:Sign`; the exact cross-account Command
Center relay task role receives only `kms:Verify`. Neither permission is reused for event delivery, model
requests, encryption, storage, or another tenant.

The Analyst web service reaches the enrollment route only through the configured
Snowman private managed prefix list. The Command Center API is default-off and
requires private workforce ingress and a live relay before it can be enabled.

## MFA truth boundary

Google's base OIDC claims prove a recent authentication but do not independently
prove which factor was used for that login. The broker therefore requires a
SHA-256 digest and review time for Google Workspace MFA/2SV policy evidence; the
receiver refuses evidence older than 120 days. This is a policy-evidence control,
not a claim of per-request authentication-method proof.

## Remaining production evidence

- implement logout, single-device and global revocation, workforce removal, and
  key-rotation flows with end-to-end audit receipts;
- build the desktop/web/mobile enrollment and session/device management UX;
- prove device-count, replay, stale-authentication, stale-MFA, role downgrade,
  broker/key rotation, and two-tenant isolation in staging;
- verify the private DNS/TLS/prefix-list path and cross-account KMS policy from
  the deployed task roles; and
- retain current Google Workspace MFA-policy evidence and sole-founder access
  review evidence in the immutable launch bundle.
