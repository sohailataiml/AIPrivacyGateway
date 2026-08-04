# ADR-0011: Use Privacy-Safe Logging, Metrics, Tracing, and Audit

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Observability systems often become secondary data stores. Logging prompts or mappings would undermine the gateway's privacy boundary.

## Decision

Use metadata-only observability.

Allowed examples:

- Request ID.
- Tenant ID where organizationally approved.
- Route.
- Status code.
- Entity counts.
- Policy action counts.
- Latency.
- Safe error codes.
- Keyed HMACs for correlation.

Prohibited examples:

- Raw prompt or response text.
- Original sensitive values.
- Decrypted mappings.
- Credentials.
- Full gateway tokens.

## Consequences

### Positive

- Reduces accidental long-term data retention.
- Supports operations without copying sensitive content.
- Simplifies privacy reviews.

### Negative

- Debugging content-related defects is harder.
- Some investigations require controlled synthetic reproduction.

## Alternatives Considered

- Full request logging with masking
- Sampling prompts
- Storing encrypted prompts
- Provider-only observability

## Implementation Constraints

- Metrics must use bounded-cardinality labels.
- Defensive log filters must mask token grammar and common secret patterns.
- Privacy regression tests must inspect logs, traces, metrics, audits, and provider mocks.
