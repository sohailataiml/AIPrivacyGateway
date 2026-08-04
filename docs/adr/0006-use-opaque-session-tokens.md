# ADR-0006: Use Opaque Session-Scoped Tokens

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Simple sequential placeholders such as `PERSON_1` are easy to guess, may occur naturally in text, and are not safely scoped.

## Decision

Use typed, opaque, random, session-scoped tokens.

Canonical format:

```text
⟦SGW:ENTITY_TYPE:RANDOM_ULID⟧
```

Repeated identical normalized values within the same tenant and session reuse the same token through an HMAC fingerprint index.

## Consequences

### Positive

- Tokens are difficult to guess.
- Repeated entities remain consistent.
- Cross-session collisions are highly unlikely.
- Strict parsing is possible.

### Negative

- Tokens are longer than human-readable placeholders.
- Token-aware streaming requires buffering.

## Alternatives Considered

- Sequential tokens
- Global deterministic hashes
- Redaction-only placeholders
- Reversible pseudonyms

## Implementation Constraints

- Tokens must not contain original-value-derived material.
- Same value in a different session must produce a different token.
- Restoration must use strict parsing, not unconstrained string replacement.
- Full tokens must not appear in logs or metrics.
