# Snowman workflow safety boundary

Status: fail-closed source hardening is implemented and locally tested. The
legacy workflow engine is not an approved production side-effect plane.

Snowman accepts `send_message` only through the relay's tenant-scoped,
in-process action sink. `send_dm` and `set_channel_topic` fail definition
validation because no end-to-end implementation exists. Legacy
`call_webhook`, `add_reaction`, and pubkey-token `request_approval` definitions
remain readable for compatibility, but runtime dispatch fails closed: they do
not perform HTTP, inherit relay credentials, or create an approval token.

External HTTP, filesystem, AWS, reviewed-program, and model operations must
enter through a purpose-specific governed boundary. Files, HTTP, AWS, and
reviewed programs use the deny-by-default Snowman tool broker. Model inference
uses the separate Snowman model gateway; a workflow cannot select a provider,
endpoint, credential, or raw prompt. The broker returns exact replay status and
signed evidence receipts; the workflow engine never retries an indeterminate
side effect.

Approval-gated actions use live Snowman workforce identity and capability
authority, exact action/snapshot digests, bounded expiry, and revocation. The
sole founder may approve normal high-impact work, including work the founder
initiated. A distinct external reviewer is required only for a named critical
exceptional control registered by operations; routine workflows must not
invent multi-person gates.

Production activation still requires a broker-backed workflow adapter,
transactional action/receipt persistence, expiration/cancellation workers, and
AWS staging evidence for replay, cancellation races, DNS rebinding/private-IP
denial, size/time ceilings, credential isolation, redaction, recovery, and
cross-tenant isolation. Until then, external workflow actions remain disabled.
