# ADR-0007: Isolate LLM Providers Behind a Protected Request Interface

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

The gateway must support external LLM providers without coupling security logic to one vendor or allowing provider adapters to receive raw sensitive input.

## Decision

Create a provider abstraction that accepts only `ProtectedChatRequest`.

The initial implementation supports one OpenAI adapter plus a mock provider for tests and demos.

## Consequences

### Positive

- Reduces risk of accidental raw-data transmission.
- Makes providers replaceable.
- Centralizes timeout, retry, and error mapping behavior.
- Enables deterministic tests.

### Negative

- Internal canonical models must be maintained.
- Provider-specific features may require adapter extensions.

## Alternatives Considered

- Direct OpenAI SDK calls in route handlers
- LiteLLM as the first implementation
- Provider-specific pipelines

## Implementation Constraints

- No provider adapter may import or accept raw request domain models.
- Caller-supplied URLs and headers are prohibited.
- Provider aliases map to server-controlled configuration.
- Automated tests must use mocked transports.
