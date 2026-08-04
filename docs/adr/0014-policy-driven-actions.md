# ADR-0014: Make Entity Handling Policy-Driven

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Different tenants and entity types require different controls. Some data should be tokenized, some blocked, some redacted, and some explicitly allowed.

## Decision

Use versioned policies to assign one of these actions per entity type:

- `ALLOW`
- `TOKENIZE`
- `REDACT`
- `PSEUDONYMIZE`
- `BLOCK`

Policies also control thresholds, providers, models, TTL, limits, and output behavior.

## Consequences

### Positive

- Behavior is explicit and reviewable.
- Different tenants can enforce different controls.
- Policy versions improve auditability.

### Negative

- Policy validation becomes security-critical.
- Misconfiguration can affect privacy behavior.

## Alternatives Considered

- Tokenize every detected entity
- Hard-coded entity actions
- Provider-specific policies
- User-selected controls per request

## Implementation Constraints

- Callers cannot weaken policy through request fields.
- Invalid policies cannot become active.
- Resolved policy snapshots are immutable for the request.
- Policy version is included in audit metadata.
