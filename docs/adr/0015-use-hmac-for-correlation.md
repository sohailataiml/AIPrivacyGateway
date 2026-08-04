# ADR-0015: Use Keyed HMACs for Sensitive Correlation

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

The system needs limited correlation for repeated values, prompts, and responses without storing plaintext. Plain unsalted hashes are vulnerable to dictionary attacks for common values.

## Decision

Use keyed HMACs for:

- Normalized value fingerprints inside a session.
- Prompt and response correlation in audit metadata.
- Rate-limit or credential-derived internal keys where appropriate.

Use separate keys or domain separation for unrelated purposes.

## Consequences

### Positive

- Stronger protection than plain hashes.
- Supports deterministic correlation.
- Reduces dictionary-attack risk when keys remain secret.

### Negative

- Key rotation affects correlation continuity.
- HMAC output remains sensitive metadata.

## Alternatives Considered

- SHA-256 without a key
- Reversible encryption
- No correlation
- Global deterministic tokens

## Implementation Constraints

- Never reuse the vault encryption key as an HMAC key.
- Include purpose-specific domain separation.
- HMAC values must not be exposed to clients.
- Tenant and session context must be included where required.
