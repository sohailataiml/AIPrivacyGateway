# ADR-0010: Use API-Key Authentication for Version 1

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Version 1 primarily serves backend applications and needs a simple, secure authentication mechanism without introducing browser login or identity-provider integration.

## Decision

Use bearer API keys for version 1.

Store only:

- Key prefix.
- One-way hash or HMAC representation.
- Tenant.
- Scopes.
- Status and expiration metadata.

OIDC and JWT support may be added later behind the same principal interface.

## Consequences

### Positive

- Simple integration for service clients.
- Clear tenant and scope mapping.
- No browser-session complexity.

### Negative

- Key rotation must be managed.
- Long-lived credentials may be mishandled by clients.
- Human user identity is not represented directly.

## Alternatives Considered

- OAuth 2.0 / OIDC
- Signed JWTs
- Mutual TLS
- Basic authentication

## Implementation Constraints

- Raw keys are shown only once.
- Raw keys are never stored or logged.
- Authentication failures use uniform public messages.
- Scopes are required for every protected endpoint.
