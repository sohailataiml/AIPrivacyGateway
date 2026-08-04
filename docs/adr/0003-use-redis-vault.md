# ADR-0003: Use Redis as the Ephemeral Token Mapping Vault

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Reversible tokenization requires low-latency session-scoped storage with automatic expiration, concurrency control, and efficient batch retrieval.

## Decision

Use Redis as the ephemeral token mapping vault.

Redis stores:

- Encrypted token-to-value mappings.
- Fingerprint-to-token indexes.
- Session metadata.
- Rate-limit state.

Redis is not used as the durable source of truth for tenants, policies, API clients, or audit records.

## Consequences

### Positive

- Low-latency access.
- Native TTL support.
- Good fit for session-scoped data.
- Atomic operations through Lua or transactions.
- Easy horizontal scaling of stateless API instances.

### Negative

- Redis becomes a critical runtime dependency.
- Persistence configuration must be carefully managed.
- Redis compromise would expose encrypted records and metadata.

## Alternatives Considered

- PostgreSQL-only storage
- In-memory process storage
- Dedicated commercial token vault
- DynamoDB
- Memcached

## Implementation Constraints

- All mapping values must be encrypted before storage.
- Every key must have a TTL.
- Every lookup must include tenant ID and session ID.
- Redis failure before provider invocation must stop the request.
- Plaintext mappings must never be stored in Redis.
