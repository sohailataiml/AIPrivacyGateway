# ADR-0000: Architecture Decision Record Process

- **Status:** Accepted
- **Date:** 2026-08-04
- **Decision owners:** Secure AI Gateway maintainers

## Context

The Secure AI Gateway contains security-sensitive architectural choices. Without a documented decision process, implementation details may drift over time and create inconsistent or insecure behavior.

## Decision

Use Architecture Decision Records under `docs/adr/`.

Each ADR must contain:

- Title
- Status
- Date
- Context
- Decision
- Consequences
- Alternatives considered
- Implementation constraints

Allowed statuses:

- Proposed
- Accepted
- Superseded
- Deprecated
- Rejected

Accepted ADRs are immutable. If a decision changes, create a new ADR and mark the older ADR as superseded.

Claude Code must read all accepted ADRs before implementing or refactoring architecture-sensitive components.

## Consequences

### Positive

- Architectural intent remains explicit.
- Security decisions can be reviewed independently from code.
- Refactors are less likely to introduce architectural drift.
- New contributors understand tradeoffs.

### Negative

- Additional documentation must be maintained.
- Some implementation work requires an ADR update first.

## Implementation Constraints

- Never silently modify an accepted ADR.
- New major dependencies, data stores, security boundaries, or provider abstractions require a new ADR.
- Pull requests that contradict accepted ADRs must either be rejected or include a superseding ADR.
