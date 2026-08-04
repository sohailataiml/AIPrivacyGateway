"""The composition root: the one place that knows how the parts fit together.

Every other module takes its collaborators as constructor arguments or reads
them off a ``Protocol``. This module is the single exception, and it exists so
that the exception is exactly one file. Nothing here contains policy, privacy,
or transport logic -- it only decides which concrete object satisfies which
seam, and in what order things open and close.

Two rules govern the wiring:

1. **Open dependencies eagerly, fail loudly.** A gateway that starts without a
   vault is a gateway that will fail every request at the worst moment. Startup
   connects to Redis and PostgreSQL and refuses to come up if it cannot.
2. **Close in reverse order, always.** Shutdown drains the audit queue before
   the database it writes to goes away, and disposes the engine last.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redis.asyncio import Redis

from app.api.adapters import AuditSinkAdapter, PolicyRepositoryAdapter
from app.audit.correlation import CorrelationHasher
from app.audit.pipeline_adapter import PipelineAuditAdapter
from app.audit.service import AuditService
from app.auth.rate_limit import RedisRateLimiter
from app.config.settings import Settings
from app.db.session import build_engine_from_settings, build_session_factory
from app.detection.config import DetectionConfig
from app.detection.engine import PresidioDetector
from app.llm.registry import build_default_registry
from app.observability.logging import get_logger
from app.pipeline.service import SecurePipeline
from app.policy.service import PolicyService
from app.restoration.pipeline import OutputPipeline
from app.tokenization.tokenizer import Tokenizer
from app.vault.crypto import EnvelopeCipher
from app.vault.keys import SettingsKeyRing
from app.vault.redis_vault import RedisTokenVault

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

logger = get_logger(__name__)

REDIS_HEALTH_TIMEOUT_SECONDS = 2.0
"""A readiness probe must answer quickly or it is useless to an orchestrator."""


@dataclass(slots=True)
class Services:
    """Everything a request handler might need, assembled once at startup."""

    settings: Settings
    engine: AsyncEngine
    session_factory: Callable[[], AsyncSession]
    redis: Redis
    pipeline: SecurePipeline
    detector: PresidioDetector
    vault: RedisTokenVault
    audit: AuditService
    rate_limiter: RedisRateLimiter

    def session_scope(self) -> AbstractAsyncContextManager[AsyncSession]:
        """Open one short-lived session."""
        return _session_scope(self.session_factory)


@asynccontextmanager
async def _session_scope(
    factory: Callable[[], AsyncSession],
) -> AsyncIterator[AsyncSession]:
    session = factory()
    try:
        yield session
    finally:
        await session.close()


async def build_services(
    settings: Settings,
    *,
    redis: Redis | None = None,
    engine: AsyncEngine | None = None,
) -> Services:
    """Construct every long-lived service. Raises if a dependency is unreachable.

    ``redis`` and ``engine`` exist so tests can supply fakes. Production passes
    neither and gets clients built from settings. Without these seams the
    lifespan would be reachable only with a live Redis and PostgreSQL, which in
    practice means it would not be tested at all.

    The detector is warmed at startup deliberately. Loading the spaCy pipeline
    costs seconds and hundreds of megabytes; paying that during startup means
    the first real request is not the one that waits for it, and a missing model
    becomes a failed deploy rather than a failed request.
    """
    engine = engine or build_engine_from_settings(settings)
    session_factory = build_session_factory(engine)

    if redis is None:
        redis = Redis.from_url(
            settings.redis_url.get_secret_value(),
            # The vault reads raw bytes: an envelope is not text, and letting
            # redis-py decode it would corrupt the ciphertext.
            decode_responses=False,
        )

    def scope() -> AbstractAsyncContextManager[AsyncSession]:
        return _session_scope(session_factory)

    vault = RedisTokenVault(redis=redis, cipher=EnvelopeCipher(SettingsKeyRing(settings)))
    detector = PresidioDetector(config=DetectionConfig())
    tokenizer = Tokenizer(vault=vault)
    output_pipeline = OutputPipeline(vault=vault)
    policy_service = PolicyService(PolicyRepositoryAdapter(scope))

    audit = AuditService(
        AuditSinkAdapter(scope),
        fail_closed=settings.audit_fail_closed,
    )
    pipeline = SecurePipeline(
        policy_service=policy_service,
        detector=detector,
        tokenizer=tokenizer,
        provider_registry=build_default_registry(settings),
        output_pipeline=output_pipeline,
        audit_service=PipelineAuditAdapter(audit, hasher=CorrelationHasher.from_settings(settings)),
        settings=settings,
    )

    return Services(
        settings=settings,
        engine=engine,
        session_factory=session_factory,
        redis=redis,
        pipeline=pipeline,
        detector=detector,
        vault=vault,
        audit=audit,
        rate_limiter=RedisRateLimiter(redis=redis),
    )


async def start_services(services: Services) -> None:
    """Bring services up and prove the dependencies are actually reachable."""
    await services.redis.ping()
    await services.audit.start()
    await services.detector.warm_up()
    logger.info("services_started")


async def stop_services(services: Services) -> None:
    """Close in reverse order of opening.

    Each step is guarded: one failing close must not skip the rest, or a failed
    shutdown leaks a connection pool into whatever replaces this process.
    """
    for name, close in (
        # The audit queue writes to PostgreSQL, so it drains before the engine
        # is disposed -- otherwise queued events die with the pool.
        ("audit", services.audit.stop),
        ("redis", services.redis.aclose),
        ("engine", services.engine.dispose),
    ):
        try:
            await close()
        except Exception:  # shutdown continues regardless of one bad step
            logger.warning("shutdown_step_failed", stage=name)
    logger.info("services_stopped")


__all__ = [
    "REDIS_HEALTH_TIMEOUT_SECONDS",
    "Services",
    "build_services",
    "start_services",
    "stop_services",
]
