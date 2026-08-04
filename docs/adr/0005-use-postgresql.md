# ADR-0005: Use PostgreSQL for Durable Metadata and Audit

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

The gateway needs durable storage for tenants, API keys, policies, provider configuration metadata, and privacy-safe audit events.

## Decision

Use PostgreSQL as the durable relational database.

Use SQLAlchemy async repositories and Alembic migrations.

## Consequences

### Positive

- Strong relational integrity.
- Mature migration tooling.
- JSONB support for versioned policy documents.
- Reliable audit persistence.
- Good operational maturity.

### Negative

- Adds another critical dependency.
- Requires schema migrations and backup procedures.

## Alternatives Considered

- SQLite
- Redis-only architecture
- MongoDB
- DynamoDB

## Implementation Constraints

- Provider secrets must not be stored directly in PostgreSQL.
- Audit tables must not contain raw prompts, responses, values, or full tokens.
- Tenant filters are mandatory in repository interfaces.
- Raw SQL interpolation is prohibited.
