"""Application entry point.

Phase 0 keeps this deliberately small: a FastAPI instance and a liveness probe
that must never depend on Redis, PostgreSQL, or any provider. Later phases add
the lifespan, middleware, and versioned routers.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.v1.health import router as health_router


def create_app() -> FastAPI:
    """Build the ASGI application."""
    application = FastAPI(
        title="Secure AI Gateway",
        version="0.1.0",
        summary="Detects and tokenizes sensitive data before it reaches an LLM provider.",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    application.include_router(health_router)
    return application


app = create_app()
