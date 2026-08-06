# ADR-0024: Record Outbound Payload Attestation

- **Status:** Accepted
- **Date:** 2026-08-04
- **Implemented:** 2026-08-06

## Context

The gateway's central claim is that originals do not reach the provider. Today
that claim rests on the pipeline being correct and on a test asserting the
property. Neither produces evidence after the fact: an audit row records what
the gateway *decided* — entity counts, actions, policy version — but nothing
about the bytes actually transmitted.

[audit-evidence.md](../audit-evidence.md) states the limit plainly: the audit
trail proves that gateway-mediated requests passed the configured controls. If
the control's result is never recorded, even that is unproven.

The obvious fix — store the outbound payload — is forbidden. ADR-0013 keeps raw
conversation content out of durable storage, and a payload archive would
recreate the sensitive-data store the whole design avoids. ADR-0015 already
established the answer for this shape of problem: a keyed HMAC proves a value
without retaining it.

## Decision

Record the outbound validator result and a keyed HMAC of the exact protected
payload. Never record the payload itself.

This implies a validator that runs in production, not only in tests: the result
being audit-worthy means there is a result.

## Consequences

### Positive

- Every request carries evidence that the outbound check ran and what it
  concluded.
- The transmitted payload can be proven after the fact, given the payload and
  the key, without ever having stored it.
- A validator in the request path makes the leak class fail closed rather than
  merely fail a test.
- Attestation covers what was *sent*, which is the property that matters,
  rather than what the pipeline intended to send.

### Negative

- A validation pass over the outbound payload costs latency on every request.
- The HMAC is only as useful as the key's custody; a rotated or lost key makes
  old attestations unverifiable.
- An HMAC proves a payload matches; it does not prove the payload was safe. It
  is evidence, not a guarantee.

## Alternatives Considered

- **Store the outbound payload.** Direct, and violates ADR-0013 by creating a
  secondary store of Confidential content. Rejected.
- **Store an unkeyed digest.** Low-entropy content becomes recoverable by brute
  force — the reason ADR-0015 requires a keyed construction. Rejected.
- **Record the validator result without the HMAC.** Proves a check ran, not what
  it ran against. Rejected as incomplete.
- **Validate in tests only.** What ships is then unverified at runtime. This is
  the status quo the ADR exists to change.

## Implementation Constraints

- The HMAC is computed over the exact bytes handed to the provider adapter,
  after protection and serialisation — not over an earlier or reconstructed
  form.
- The HMAC is keyed, using the correlation key hierarchy of ADR-0015. The key
  never enters audit rows, logs, or metrics.
- The validator runs before transmission. A failed validation blocks the request
  per ADR-0008; it never downgrades to a warning.
- The validator result and the payload HMAC are recorded on both the success and
  the blocked path — a request stopped by validation is the case most worth
  auditing.
- Neither the payload, nor any substring of it, nor any detected original value
  appears in the audit record. Counts and the HMAC only.
- The audit record's existing null-by-default correlation HMACs are populated as
  part of this work, or removed. A column that is always null is worse than an
  absent one.

## As Built (Phase 6)

`app/documents/outbound.py`, `app/documents/pipeline.py`, and the two nullable
columns added by `migrations/versions/0003_outbound_attestation.py`.

**What is attested.** `serialize_outbound` produces one canonical byte string
per protected request: framing version, provider alias, model alias, policy
version, and every message's role and content, each length-prefixed so no
regrouping of the same bytes can collide. It is deliberately **not** the
provider's wire format — an OpenAI JSON body belongs to that adapter and would
change with its SDK, so attesting it would tie the audit trail to a vendor and
let an adapter upgrade silently invalidate every old digest.

The request id is deliberately **outside** the frame. Two identical payloads
must attest identically or the digest cannot be recomputed, and a digest nobody
can recompute proves nothing.

**Where the digest goes.** `audit_events.outbound_hmac`, under its own domain
constant in `CorrelationHasher` so an outbound attestation can never equal the
prompt digest of the same content. The column is not called `payload_hmac`:
`AuditRecord` screens field names against a prohibited-substring list that
includes `payload`, and the screen is right to.

**The validator that makes the result audit-worthy.** `scan_outbound` runs the
detector over the exact payload immediately before transmission and blocks on
any detection the policy would act on. `audit_events.outbound_scan` records
`clean` or `blocked`, on both paths.

One implementation detail is load-bearing and non-obvious: **detections falling
inside a gateway token or a redaction placeholder are discarded before the
verdict.** A token carries a 26-character identifier that recognizers read as an
account number, so without that exclusion the scan would flag the very
substitutions protection had just made, block every document, and be switched
off within a day.

**Both routes, one component.** `/v1/chat` and
`POST /v1/documents/{id}/process` transmit through the *same*
`OutboundGateway` instance, asserted on object identity through
`build_services`. A caller cannot reach a provider adapter without passing
through `OutboundGateway.send`, and the scan runs inside it before the adapter
is touched — so there is no route on which the check can be forgotten.

`OutboundGateway.send` accepts an optional `invoke` callable, because the chat
pipeline wraps its provider call in a request deadline and a concurrency
semaphore and the document path needs neither. That injects *how* the adapter is
awaited, never *whether*: the verdict has already been decided by the time the
callable runs.

**Correlation HMACs.** `prompt_hmac`, `response_hmac`, `session_id_hash`,
`outbound_hmac`, and `outbound_scan` are populated on **both** routes. The
"populated or removed" requirement is met; no column is always null.

They remain nullable, and stay null on one path deliberately: a request refused
*before* serialization — an unpermitted provider, an oversized message, a
blocked entity type — has no payload to attest, and a null column saying so is
more honest than a digest of something that was never assembled.

**One finding worth recording.** The scan runs over **each message
separately**, not the concatenation. Presidio's NER is context-sensitive:
`"An unremarkable week, clinically."` yields nothing alone and yields
`DATE_TIME` on `"week"` at 0.85 once another sentence precedes it. Scanning the
joined text therefore reports entities no protection pass could have seen —
protection ran per message — and refuses ordinary traffic for a value that
exists only at the seam. Per-message scanning makes the verdict mean "protection
missed something" rather than "the concatenation reads differently". The cost is
that an entity formed *across* a message boundary goes unreported, which is the
right trade: no real value spans two messages, and the artifacts demonstrably
do.

Tests: `tests/unit/test_outbound.py` for the serialization collision
properties, the scan's two halves, and per-message scanning;
`tests/unit/test_document_pipeline.py` for the blocked path still writing its
evidence and the attested bytes being the transmitted bytes;
`tests/privacy/test_document_workflow.py` for the whole document journey; and
`tests/privacy/test_outbound_conformance.py` for both routes against a provider
that records what it received, including that they share one gateway object.
