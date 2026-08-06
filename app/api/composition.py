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

from collections.abc import AsyncIterator, Awaitable, Callable
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
from app.documents.analysis.analyzer import DocumentAnalyzer
from app.documents.crypto import DocumentCipher
from app.documents.extraction.runner import SubprocessExtractionRunner
from app.documents.processing import DocumentProcessor
from app.documents.protocol import DocumentStore
from app.documents.segmentation import Segmenter
from app.documents.service import DocumentService
from app.documents.storage.s3 import S3CompatibleDocumentStore
from app.llm.registry import build_default_registry
from app.observability.logging import get_logger
from app.pipeline.service import SecurePipeline
from app.policy.service import PolicyService
from app.restoration.pipeline import OutputPipeline
from app.tokenization.tokenizer import Tokenizer
from app.vault.crypto import EnvelopeCipher
from app.vault.keys import DocumentSettingsKeyRing, SettingsKeyRing
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
    documents: DocumentService | None
    """``None`` when ``DOCUMENTS_ENABLED`` is false and the routes are absent."""

    document_processor: DocumentProcessor | None
    """Extraction and segmentation. Present exactly when ``documents`` is.

    Reached only through ``document_analyzer``. It is assembled here so its
    worker bound and its shutdown are wired once, in the one place that knows
    how parts fit.
    """

    document_analyzer: DocumentAnalyzer | None
    """Detection over documents. Present exactly when ``documents`` is.

    Nothing calls it yet -- no route reaches document detection until the phase
    that protects a document. It owns no handle of its own, so it needs no
    closer: the processor it reads through is closed on its own line below.
    """

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
    document_store: DocumentStore | None = None,
) -> Services:
    """Construct every long-lived service. Raises if a dependency is unreachable.

    ``redis``, ``engine``, and ``document_store`` exist so tests can supply
    fakes. Production passes none of them and builds clients from settings. Without these seams the
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

    documents = (
        _build_document_service(settings, scope, document_store)
        if settings.documents_enabled
        else None
    )

    document_processor = (
        _build_document_processor(settings, documents) if documents is not None else None
    )
    document_analyzer = (
        _build_document_analyzer(settings, document_processor, detector, policy_service)
        if document_processor is not None
        else None
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
        documents=documents,
        document_processor=document_processor,
        document_analyzer=document_analyzer,
    )


def _build_document_service(
    settings: Settings,
    scope: Callable[[], AbstractAsyncContextManager[AsyncSession]],
    store: DocumentStore | None = None,
) -> DocumentService:
    """Assemble document storage. Its own key ring, separate from the vault's."""
    return DocumentService(
        store=store if store is not None else S3CompatibleDocumentStore.from_settings(settings),
        cipher=DocumentCipher(
            DocumentSettingsKeyRing(settings),
            chunk_bytes=settings.document_chunk_bytes,
        ),
        session_scope=scope,
        max_document_bytes=settings.max_document_bytes,
    )


def _build_document_processor(settings: Settings, documents: DocumentService) -> DocumentProcessor:
    """Assemble extraction and segmentation over the storage service.

    Reads through ``DocumentService`` rather than the store directly, so it
    inherits the tenant and user scoping and the per-document decryption
    instead of opening a second, laxer path to the same bytes.
    """
    return DocumentProcessor(
        source=documents,
        runner=SubprocessExtractionRunner(
            max_workers=settings.extraction_max_workers,
            timeout_seconds=settings.extraction_timeout_seconds,
            max_characters=settings.max_extracted_characters,
        ),
        segmenter=Segmenter(
            max_characters=settings.segment_max_characters,
            overlap_characters=settings.segment_overlap_characters,
        ),
        max_document_bytes=settings.max_document_bytes,
    )


def _build_document_analyzer(
    settings: Settings,
    processor: DocumentProcessor,
    detector: PresidioDetector,
    policies: PolicyService,
) -> DocumentAnalyzer:
    """Assemble detection over documents.

    Shares the one warmed ``PresidioDetector`` with the chat pipeline rather
    than building a second. A separate instance would load spaCy again --
    hundreds of megabytes for no benefit -- and, worse, could be configured
    differently, so a value protected in a prompt might not be protected in a
    document.
    """
    return DocumentAnalyzer(
        source=processor,
        detector=detector,
        policies=policies,
        max_entities=settings.max_document_entities,
        concurrency=settings.document_detection_concurrency,
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
    closers: list[tuple[str, Callable[[], Awaitable[object]]]] = [
        # The audit queue writes to PostgreSQL, so it drains before the engine
        # is disposed -- otherwise queued events die with the pool.
        ("audit", services.audit.stop),
        ("redis", services.redis.aclose),
    ]
    if services.document_processor is not None:
        # Before the storage service it reads through, so a worker cannot be
        # mid-extraction against a store that has already been closed.
        closers.append(("document_processor", services.document_processor.aclose))
    if services.documents is not None:
        closers.append(("documents", services.documents.aclose))
    closers.append(("engine", services.engine.dispose))

    for name, close in closers:
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
