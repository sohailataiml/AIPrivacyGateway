# ADR-0013: Do Not Persist Raw Conversations in Version 1

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Persisting raw prompts and responses would create a new high-value sensitive-data store and increase compliance, retention, encryption, and access-control requirements.

## Decision

Do not persist raw prompts or responses in PostgreSQL, Redis, logs, traces, metrics, or audit.

Only short-lived encrypted token mappings are retained in Redis for the configured session TTL.

## Consequences

### Positive

- Strong data minimization.
- Reduced breach impact.
- Simpler retention and deletion behavior.

### Negative

- No built-in conversation history.
- Limited content-level debugging.
- Clients must manage conversation state.

## Alternatives Considered

- Encrypted conversation storage
- Tenant-configurable retention
- Provider-managed history
- Redacted-only history

## Implementation Constraints

- Chat history must be supplied by the client on each request.
- Future raw or redacted conversation storage requires a new ADR and threat-model update.
