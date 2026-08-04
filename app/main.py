"""Application entry point and lifecycle.

The middleware order below is deliberate. Starlette applies middleware in
reverse registration order, so registering request-id last makes it the
outermost layer -- every other layer, including the body-size rejection, can
then reference a request id that already exists.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.errors import register_exception_handlers
from app.api.middleware import (
    BodySizeLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from app.api.v1.health import router as health_router
from app.config.settings import Settings, get_settings
from app.observability.logging import configure_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open shared resources on startup and close them on shutdown.

    Redis, PostgreSQL, and the detector engine are attached here as their
    packages land. Whatever is opened must be closed in the finally block --
    a leaked connection pool outlives the process that made it.
    """
    settings: Settings = app.state.settings
    logger.info("startup", reason=settings.app_env.value)
    try:
        yield
    finally:
        logger.info("shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application."""
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_output=settings.is_production)

    application = FastAPI(
        title="Secure AI Gateway",
        version="0.1.0",
        summary="Detects and tokenizes sensitive data before it reaches an LLM provider.",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    application.state.settings = settings

    register_exception_handlers(application)

    # Innermost first.
    application.add_middleware(SecurityHeadersMiddleware)
    if settings.cors_allowed_origins:
        # CORS is off unless a deployment opts in explicitly; production also
        # rejects a wildcard at settings-validation time.
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        )
    application.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    application.add_middleware(RequestIdMiddleware)

    application.include_router(health_router)
    return application


app = create_app()
