# ADR-0008: Fail Closed for Privacy-Critical Dependencies

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

A common but unsafe failure strategy is to bypass privacy processing when a detector, vault, or policy service is unavailable.

## Decision

The gateway fails closed when any privacy-critical component cannot complete safely.

Privacy-critical components include:

- Authentication and authorization.
- Policy resolution.
- Sensitive-data detection.
- Tokenization.
- Vault persistence.
- Restoration authorization.
- Output token resolution.

## Consequences

### Positive

- Prevents accidental raw-data transmission.
- Makes security guarantees predictable.
- Simplifies incident analysis.

### Negative

- Dependency failures reduce availability.
- Users may receive errors even when the LLM provider is healthy.

## Alternatives Considered

- Bypass detection on failure
- Redact all content on failure
- Send directly to provider with warning
- Queue request for later processing

## Implementation Constraints

- Provider invocation must never occur after a detector or vault failure.
- No insecure fallback path may exist.
- Errors must be sanitized and machine-readable.
- Health and alerting must make fail-closed outages visible.
