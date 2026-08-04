# ADR-0016: Use Mocked Provider Transports for Automated Tests

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Automated tests must be deterministic, inexpensive, private, and capable of inspecting exact provider-bound payloads.

## Decision

Use mocked HTTP transports or provider fakes for all automated tests.

A local mock provider may be included for Docker Compose demonstrations.

## Consequences

### Positive

- No external data transmission during tests.
- Exact payload inspection is possible.
- Tests are deterministic and fast.
- CI does not require provider credentials.

### Negative

- Mocks may diverge from provider behavior.
- Separate controlled integration testing may still be needed.

## Alternatives Considered

- Live provider calls in CI
- Recorded provider responses
- SDK-only unit mocks without HTTP inspection

## Implementation Constraints

- CI must fail if an unexpected external network call is attempted.
- Privacy tests must assert originals are absent from provider-bound payloads.
- Live-provider verification, if added, must be opt-in and use synthetic data only.
