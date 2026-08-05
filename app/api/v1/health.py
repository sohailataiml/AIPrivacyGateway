"""Health probes.

The split matters to an orchestrator. ``/health/live`` answers from process
state alone: if it fails, the process is broken and restarting is the right
response. ``/health/ready`` reports whether dependencies are reachable: if it
fails, restarting fixes nothing, and the right response is to stop routing
traffic here until Redis or PostgreSQL recovers.

Tying liveness to a dependency is a classic way to turn a database blip into a
cluster-wide restart loop, so liveness here touches nothing.
"""

from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

from app.observability.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/health", tags=["health"])

DEPENDENCY_TIMEOUT_SECONDS = 2.0
"""A probe that hangs is worse than one that fails: the orchestrator waits."""

STATUS_UP = "up"
STATUS_DOWN = "down"
STATUS_UNKNOWN = "unknown"


class LivenessResponse(BaseModel):
    """Process-level liveness. Never reflects dependency state."""

    status: Literal["alive"]


class ReadinessResponse(BaseModel):
    """Dependency readiness and the per-dependency status names."""

    status: Literal["ready", "not_ready"]
    dependencies: dict[str, str]


@router.get("/live", response_model=LivenessResponse, summary="Liveness probe")
async def live() -> LivenessResponse:
    return LivenessResponse(status="alive")


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness probe")
async def ready(request: Request, response: Response) -> ReadinessResponse:
    """Report dependency reachability without disclosing any of it.

    Values are ``up``/``down``/``unknown`` only. A host, port, database name, or
    driver error message here would hand an unauthenticated caller a map of the
    internal network -- this endpoint is typically the least protected one in
    the deployment.
    """
    services = getattr(request.app.state, "services", None)
    if services is None:
        # Startup has not completed, or the app was built without wiring.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(
            status="not_ready",
            dependencies={"redis": STATUS_UNKNOWN, "database": STATUS_UNKNOWN},
        )

    redis_status, database_status = await asyncio.gather(
        _probe("redis", services.redis.ping()),
        _probe("database", _database_ping(services)),
    )

    dependencies = {"redis": redis_status, "database": database_status}

    documents = getattr(services, "documents", None)
    if documents is not None:
        # Only when uploads are enabled. Reporting a dependency the deployment
        # does not use would make readiness fail for a capability nobody asked
        # for -- and probing the bucket, rather than trusting configuration, is
        # what keeps a readiness pass from being followed by failing uploads.
        dependencies["object_store"] = await _probe("object_store", documents.health())

    healthy = all(value == STATUS_UP for value in dependencies.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ready" if healthy else "not_ready",
        dependencies=dependencies,
    )


async def _probe(name: str, awaitable: object) -> str:
    """Run one dependency check, reporting only up or down."""
    try:
        async with asyncio.timeout(DEPENDENCY_TIMEOUT_SECONDS):
            await awaitable  # type: ignore[misc]
    except Exception:  # any failure at all means the dependency is not reachable
        # The exception text can carry a connection string. Log the dependency
        # name and nothing else.
        logger.warning("dependency_unavailable", stage=name)
        return STATUS_DOWN
    return STATUS_UP


async def _database_ping(services: object) -> None:
    """Cheapest possible round trip that proves the pool can serve a query."""
    async with services.session_scope() as session:  # type: ignore[attr-defined]
        await session.execute(text("SELECT 1"))
