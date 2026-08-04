# ADR-0012: Defer Streaming Until Synchronous Restoration Is Proven

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Provider streaming can split security tokens across chunks. Naive per-chunk replacement can leak token fragments, corrupt output, or fail restoration.

## Decision

Version 1 supports synchronous responses only.

Streaming may be implemented after:

- Strict token parsing is stable.
- Partial-token buffering is designed.
- Cancellation and vault failure behavior are tested.
- Privacy tests cover chunk boundaries.

## Consequences

### Positive

- Reduces initial implementation risk.
- Keeps restoration behavior deterministic.
- Allows privacy invariants to be proven first.

### Negative

- Higher perceived latency for users.
- Some provider capabilities remain unavailable.

## Alternatives Considered

- Immediate streaming with naive replacement
- Server-sent events with full response buffering
- Streaming without restoration

## Implementation Constraints

- Do not expose `/chat/stream` in version 1.
- A future streaming ADR must supersede this decision.
