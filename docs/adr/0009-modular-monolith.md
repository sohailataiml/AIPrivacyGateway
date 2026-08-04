# ADR-0009: Begin as a Modular Monolith

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

The system contains clear functional modules but does not initially require independently deployable microservices. Premature service separation would increase operational and security complexity.

## Decision

Implement version 1 as a modular monolith with explicit internal interfaces.

Modules include:

- API
- Authentication
- Policy
- Detection
- Tokenization
- Vault
- Provider adapters
- Restoration
- Audit
- Observability

## Consequences

### Positive

- Easier local development and testing.
- Fewer network trust boundaries.
- Simpler deployment.
- Easier privacy regression testing.

### Negative

- Process-level faults affect the entire gateway.
- Teams cannot deploy modules independently.

## Alternatives Considered

- Microservices from day one
- Serverless functions
- Single-file monolith

## Implementation Constraints

- Domain modules must communicate through interfaces.
- Routes must not contain business logic.
- Provider adapters must not access the vault.
- Service extraction must be possible without redesigning domain contracts.
