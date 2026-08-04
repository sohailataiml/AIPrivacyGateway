"""Startup, shutdown, and readiness.

``httpx.ASGITransport`` does not run the lifespan, so every other test in this
suite exercises the app with none of this code executing. These tests use
``asgi_lifespan.LifespanManager`` to actually start and stop the application,
against a fake Redis and an in-memory database.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import fakeredis.aioredis
import httpx
import pytest
from asgi_lifespan import LifespanManager
from sqlalchemy.ext.asyncio import create_async_engine

from app.api.composition import Services, build_services, stop_services
from app.config.settings import Settings
from app.db.base import Base
from app.main import create_app


async def _raise_unreachable(*_args: object, **_kwargs: object) -> None:
    """Stand in for a dependency that cannot be reached."""
    raise ConnectionError("simulated outage")


@pytest.fixture
def settings() -> Settings:
    return Settings(app_env="test")


@pytest.fixture
async def services(settings: Settings) -> AsyncIterator[Services]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    built = await build_services(
        settings,
        redis=fakeredis.aioredis.FakeRedis(decode_responses=False),
        engine=engine,
    )
    yield built
    await stop_services(built)


class TestStartup:
    async def test_state_carries_everything_auth_reads_by_name(
        self, settings: Settings, services: Services
    ) -> None:
        # app.auth.dependencies looks these up on app.state by name and fails
        # closed when one is absent, which is correct but hard to diagnose.
        app = create_app(settings)
        app.state.services = services

        async with LifespanManager(app):
            for name in ("redis", "db_session_factory", "rate_limiter", "settings"):
                assert getattr(app.state, name, None) is not None, name

    async def test_startup_proves_redis_is_reachable(
        self, settings: Settings, services: Services, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A gateway that starts without a vault fails every request later. It
        # should refuse to come up instead.
        monkeypatch.setattr(type(services.redis), "ping", _raise_unreachable)
        app = create_app(settings)
        app.state.services = services

        with pytest.raises(ConnectionError):
            async with LifespanManager(app):
                pass

    async def test_a_failed_startup_still_releases_handles(
        self, settings: Settings, services: Services, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        app = create_app(settings)
        app.state.services = services

        disposed: list[str] = []

        async def explode(_self: object) -> None:
            raise RuntimeError("detector model missing")

        original_dispose = type(services.engine).dispose

        async def record_dispose(self: object, close: bool = True) -> None:
            disposed.append("engine")
            await original_dispose(self, close)

        monkeypatch.setattr(type(services.detector), "warm_up", explode)
        monkeypatch.setattr(type(services.engine), "dispose", record_dispose)

        with pytest.raises(RuntimeError, match="detector model missing"):
            async with LifespanManager(app):
                pass

        # Startup had already opened the pool before it failed. It must be
        # released, or a crash-looping deploy leaks a connection pool per try.
        assert disposed == ["engine"]


class TestShutdown:
    async def test_one_failing_close_does_not_skip_the_others(
        self, settings: Settings, services: Services, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A leaked pool outlives the process that made it, so a failure in one
        # close step must not abandon the remaining steps.
        closed: list[str] = []

        async def explode(_self: object) -> None:
            raise RuntimeError("audit drain failed")

        original_dispose = type(services.engine).dispose

        async def record_dispose(self: object, close: bool = True) -> None:
            closed.append("engine")
            await original_dispose(self, close)

        monkeypatch.setattr(type(services.audit), "stop", explode)
        monkeypatch.setattr(type(services.engine), "dispose", record_dispose)

        await stop_services(services)

        # The audit close raised, yet the engine was still disposed.
        assert closed == ["engine"]


class TestReadiness:
    @pytest.fixture
    async def client(
        self, settings: Settings, services: Services
    ) -> AsyncIterator[httpx.AsyncClient]:
        app = create_app(settings)
        app.state.services = services
        async with LifespanManager(app):
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as instance:
                yield instance

    async def test_reports_ready_when_dependencies_answer(self, client: httpx.AsyncClient) -> None:
        response = await client.get("/health/ready")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ready"
        assert body["dependencies"] == {"redis": "up", "database": "up"}

    async def test_reports_503_when_a_dependency_is_down(
        self, client: httpx.AsyncClient, services: Services, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(type(services.redis), "ping", _raise_unreachable)

        response = await client.get("/health/ready")

        assert response.status_code == 503
        assert response.json()["dependencies"]["redis"] == "down"

    async def test_readiness_discloses_no_infrastructure_detail(
        self, client: httpx.AsyncClient, services: Services, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # This endpoint is usually the least protected one in a deployment.
        monkeypatch.setattr(type(services.redis), "ping", _raise_unreachable)

        response = await client.get("/health/ready")

        text = response.text.lower()
        for leak in ("redis://", "localhost", "127.0.0.1", "sqlite", "password", "connect"):
            assert leak not in text, f"readiness disclosed {leak!r}"

    async def test_liveness_stays_up_when_dependencies_are_down(
        self, client: httpx.AsyncClient, services: Services, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Tying liveness to a dependency turns a database blip into a
        # cluster-wide restart loop.
        monkeypatch.setattr(type(services.redis), "ping", _raise_unreachable)

        response = await client.get("/health/live")

        assert response.status_code == 200
        assert response.json() == {"status": "alive"}
