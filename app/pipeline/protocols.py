"""Structural seams the pipeline depends on.

The pipeline is the one module that touches every other package, so it is also
the one module most able to create import cycles. Everything it needs from a
*downstream* stage is declared here as a ``Protocol`` instead of imported from
that stage's package.

Two of these -- ``OutputPipelineLike`` and ``AuditServiceLike`` -- describe
packages that are built independently. Depending on their shape rather than
their identity means this module compiles, type-checks, and is fully testable
before either concrete implementation exists, and neither can drag its Redis,
database, or queue machinery into the request path's import graph.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from app.domain.models import (
    DetectedEntity,
    PrivacySummary,
    ProviderResponse,
    ProviderUsage,
    TransformedText,
)
from app.policy.models import PolicySnapshot
from app.tokenization.protocols import PolicyLike


@runtime_checkable
class PolicyResolverLike(Protocol):
    """Resolves the active policy and authorizes the requested destination.

    Satisfied by :class:`app.policy.service.PolicyService`. The provider and
    model allowlist checks happen inside ``resolve``, which is why this is the
    first call the pipeline makes.
    """

    async def resolve(self, *, tenant_id: UUID, provider: str, model: str) -> PolicySnapshot:
        """Return the tenant's active snapshot, or raise a domain error."""
        ...


@runtime_checkable
class DetectorLike(Protocol):
    """Finds sensitive spans. Satisfied by every ``app.detection.Detector``.

    Restated here rather than imported so the pipeline's contract stays visible
    at its own boundary; the two are the same shape by construction, and the
    test suite asserts it.
    """

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        """Return non-overlapping entities, or raise if the engine cannot run."""
        ...


@runtime_checkable
class TokenizerLike(Protocol):
    """Applies policy actions to one message and persists any mappings.

    ``transform`` is the only call in the pipeline that writes to the vault, and
    every path to a provider goes through it first.
    """

    async def transform(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        text: str,
        entities: Any,
        policy: PolicyLike,
    ) -> TransformedText:
        """Return protected text plus its mappings and counts-only summary."""
        ...


@runtime_checkable
class RestoredOutputLike(Protocol):
    """What restoration hands back.

    Read-only properties, because the pipeline consumes this and must not be
    able to edit restored text on its way to the caller.
    """

    @property
    def text(self) -> str:
        """Provider output with resolvable tokens replaced by originals."""
        ...

    @property
    def summary(self) -> PrivacySummary:
        """Counts only: ``restored`` and ``unknown_tokens``."""
        ...

    @property
    def usage(self) -> ProviderUsage | None:
        """Provider token accounting, passed through unchanged."""
        ...


@runtime_checkable
class OutputPipelineLike(Protocol):
    """Validates provider output and restores authorized tokens.

    ``policy`` is intentionally untyped here: restoration reads exactly one
    field from the snapshot and declares its own narrower protocol for it.
    """

    async def restore(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        response: ProviderResponse,
        policy: Any,
    ) -> RestoredOutputLike:
        """Return restored output, or raise if restoration cannot be completed."""
        ...


@runtime_checkable
class AuditServiceLike(Protocol):
    """Appends one privacy-safe record per request.

    Deliberately loose. The audit package owns the field list and the
    prohibited-field enforcement; the pipeline's job is to hand over counts and
    identifiers and to honour the configured fail-open or fail-closed policy.
    """

    async def record(self, **fields: Any) -> None:
        """Append one event. Never called with message content."""
        ...
