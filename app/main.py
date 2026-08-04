"""Application entry point and lifecycle.

The middleware order below is deliberate. Starlette applies middleware in
reverse registration order, so registering request-id last makes it the
outermost layer -- every other layer, including the body-size rejection, can
then reference a request id that already exists.

Wiring lives in :mod:`app.api.composition`; this module only decides *when* it
happens. Services are built and connected during startup so that an unreachable
Redis or PostgreSQL fails the deploy rather than every subsequent request.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.composition import build_services, start_services, stop_services
from app.api.errors import register_exception_handlers
from app.api.middleware import (
    BodySizeLimitMiddleware,
    MetricsMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)
from app.api.v1.chat import router as chat_router
from app.api.v1.detect import router as detect_router
from app.api.v1.health import router as health_router
from app.api.v1.metrics import router as metrics_router
from app.api.v1.sessions import router as sessions_router
from app.config.settings import Settings, get_settings
from app.observability.logging import configure_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open shared resources on startup and close them on shutdown.

    ``app.state`` is populated with the individual collaborators as well as the
    ``Services`` bundle, because ``app.auth.dependencies`` reads ``redis``,
    ``db_session_factory``, ``rate_limiter`` and ``settings`` off state by name.
    Missing any of them makes authentication fail closed, which is the correct
    behaviour but a confusing way to discover a wiring mistake.
    """
    settings: Settings = app.state.settings
    logger.info("startup", reason=settings.app_env.value)

    services = getattr(app.state, "services", None) or await build_services(settings)
    try:
        await start_services(services)
    except Exception:
        # Startup got far enough to open handles before failing. Release them,
        # then let the failure propagate so the process does not serve traffic.
        await stop_services(services)
        logger.error("startup_failed")
        raise

    app.state.services = services
    app.state.redis = services.redis
    app.state.db_session_factory = services.session_factory
    app.state.rate_limiter = services.rate_limiter

    try:
        yield
    finally:
        await stop_services(services)
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
    # Outside the size limit so a rejected oversized body is still counted, and
    # inside the request id so a metric and a log line describe the same span.
    application.add_middleware(MetricsMiddleware)
    application.add_middleware(RequestIdMiddleware)

    application.include_router(health_router)
    application.include_router(chat_router)
    application.include_router(detect_router)
    application.include_router(sessions_router)
    if settings.metrics_enabled:
        # Absent rather than forbidden when disabled: a route that exists and
        # refuses still confirms the deployment has metrics worth asking for.
        application.include_router(metrics_router)
    return application


app = create_app()
