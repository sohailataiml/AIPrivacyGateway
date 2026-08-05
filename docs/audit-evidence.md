# Audit Evidence and Compliance Limitations

What an audit record contains, what it must never contain, and — importantly —
what it does and does not prove.

## Recorded

Request ID, document ID, session HMAC, tenant, policy version, detector config
version, code version, entity counts, action counts, outbound validator result,
provider alias, model alias, protected-payload HMAC, character counts, timings,
timestamp, and result code.

Three of these exist to make a record reproducible rather than merely
descriptive:

- **Policy version** — which rules were in force. Policy versions are immutable,
  so this is sufficient to reconstruct the decision.
- **Detector config version** — which recognizers, thresholds, and allowlists
  were active. Detection quality changes over time; an audit row without this
  cannot be interpreted later.
- **Code version** — which build produced the row.

## Never recorded

Original values, raw prompts, raw responses, raw documents, decrypted mappings,
and full tokens.

This is not a logging-hygiene preference. Audit systems are durable, widely
readable, and long-retained; an audit row containing an original value converts
the compliance store into a secondary sensitive-data store with weaker controls
than the vault (ADR-0013). Correlation is done with keyed HMACs (ADR-0015) so a
value can be *matched* without being *retained*.

## What the trail proves

The audit trail proves that **gateway-mediated requests passed the configured
controls**: that a policy of a known version was applied, that detection ran
under a known configuration, that the outbound validator returned a given
result, and that the payload transmitted matches a recorded HMAC (ADR-0024).

## What it does not prove

- **It does not prove the absence of detector false negatives.** The gateway
  can guarantee transformation of detected spans, not perfect detection of every
  possible sensitive value. An audit row showing "2 entities detected" is
  evidence about the detector's output, not about the input's true content.
- **It does not prove the absence of bypass traffic** unless egress is enforced.
  A record exists for every request *through the gateway*. An application that
  calls a provider directly leaves no row at all — the absence of evidence looks
  identical to the absence of traffic. Network-level egress restriction is what
  closes this, and it is outside the application.
- **It is not a compliance certification.** It is evidence a control ran, which
  is a prerequisite for compliance work, not a substitute for it.

Stating these limits is deliberate. An audit trail that is trusted for more than
it proves is worse than one whose boundaries are understood.

## Related decisions

- ADR-0011 — privacy-safe observability
- ADR-0013 — no raw conversation storage
- ADR-0015 — HMAC correlation
- ADR-0024 — outbound payload attestation
- [data-classification.md](data-classification.md) — why audit metadata is Internal
