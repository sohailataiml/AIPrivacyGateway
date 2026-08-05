# ADR-0024: Record Outbound Payload Attestation

- **Status:** Accepted
- **Date:** 2026-08-04

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
