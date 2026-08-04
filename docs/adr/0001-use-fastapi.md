# ADR-0001: Use FastAPI for the HTTP API

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

The gateway requires an asynchronous Python API framework with strong request validation, OpenAPI generation, middleware support, dependency injection, and a mature ecosystem.

## Decision

Use FastAPI as the HTTP API framework.

Use:

- Pydantic models for external request and response validation.
- FastAPI dependencies for authentication and authorization.
- Lifespan handlers for Redis and PostgreSQL initialization.
- Explicit exception handlers for safe public errors.
- Uvicorn as the ASGI server.

## Consequences

### Positive

- Strong typing at API boundaries.
- Native OpenAPI documentation.
- Good support for async I/O.
- Easy test integration.
- Clear dependency injection model.

### Negative

- Framework-specific dependency patterns may spread into domain code.
- Developers may be tempted to place business logic inside routes.

## Alternatives Considered

- Flask
- Django REST Framework
- Starlette
- Litestar

## Implementation Constraints

- Route modules must remain thin.
- Domain services must not import FastAPI.
- Provider, vault, detector, and policy logic must remain framework-independent.
- Request and response bodies must never be logged by middleware.
