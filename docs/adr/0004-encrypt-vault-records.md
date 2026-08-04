# ADR-0004: Encrypt Vault Records at the Application Layer

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Transport encryption and encrypted disks do not protect mapping values from all Redis compromise scenarios. The gateway needs an additional protection layer for sensitive token mappings.

## Decision

Encrypt every token mapping using authenticated encryption before writing it to Redis.

Use:

- AES-256-GCM or ChaCha20-Poly1305.
- Random nonce per record.
- Associated data containing schema version, tenant ID, session ID, and token ID.
- Key identifiers for rotation.
- Runtime-loaded keys from a secrets manager or environment-backed development configuration.

## Consequences

### Positive

- Redis snapshots and memory dumps do not directly reveal plaintext values.
- Ciphertext tampering is detected.
- Associated data protects context binding.

### Negative

- Key management becomes critical.
- Rotation and backward decryption require key-ring support.
- Application CPU overhead increases slightly.

## Alternatives Considered

- Redis encryption at rest only
- TLS only
- Database-level encryption
- Plaintext mappings in a private network

## Implementation Constraints

- Production must reject weak or default keys.
- Nonces must never be reused with the same key.
- Encryption keys must never be logged or stored in PostgreSQL.
- Decryption must validate tenant and session associated data.
