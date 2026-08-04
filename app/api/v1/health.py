"""Health probes.

``/health/live`` answers from process state only. ``/health/ready`` gains real
dependency checks in Phase 13; until the clients exist it reports the same
shape so orchestration configuration does not have to change later.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/health", tags=["health"])


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
async def ready() -> ReadinessResponse:
    # Phase 13 replaces this with real Redis/PostgreSQL checks. It reports no
    # hostnames or credentials by design -- only a dependency name and a state.
    return ReadinessResponse(status="ready", dependencies={})
