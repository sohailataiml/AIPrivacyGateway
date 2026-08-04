"""Phase 0 acceptance: the application builds and liveness answers."""

from __future__ import annotations

import httpx
import pytest
from app.main import create_app


@pytest.fixture
def client() -> httpx.AsyncClient:
    app = create_app()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_liveness_returns_alive(client: httpx.AsyncClient) -> None:
    # Arrange / Act
    async with client:
        response = await client.get("/health/live")

    # Assert
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


async def test_liveness_does_not_touch_dependencies() -> None:
    # Liveness must answer even with no Redis, PostgreSQL, or provider configured.
    app = create_app()
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health/live")

    assert response.status_code == 200


async def test_openapi_schema_is_generated() -> None:
    app = create_app()
    schema = app.openapi()

    assert schema["info"]["title"] == "Secure AI Gateway"
    assert "/health/live" in schema["paths"]
