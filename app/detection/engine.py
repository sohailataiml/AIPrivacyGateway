"""The production detector: Presidio plus this package's custom recognizers."""

from __future__ import annotations

import asyncio
from typing import Any

from app.detection.analyzer import get_analyzer_engine
from app.detection.config import DetectionConfig
from app.detection.postprocess import Candidate, finalize
from app.domain.errors import DetectorUnavailableError, UnsupportedLanguageError
from app.domain.models import DetectedEntity


class PresidioDetector:
    """Detects sensitive spans with a lazily built, process-wide analyzer.

    Cheap to construct and safe to share: the expensive engine lives in the
    module-level cache in :mod:`app.detection.analyzer`, so many detectors with
    the same configuration cost one spaCy load between them.
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config if config is not None else DetectionConfig()

    @property
    def config(self) -> DetectionConfig:
        return self._config

    async def warm_up(self) -> None:
        """Build the analyzer now so the first request does not wait for spaCy.

        Raises:
            DetectorUnavailableError: The engine could not be constructed.
        """
        await asyncio.to_thread(get_analyzer_engine, self._config)

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        """Return non-overlapping entities sorted by ``(start, end)``.

        See :class:`app.detection.base.Detector` for the full contract.
        """
        if not self._config.supports_language(language):
            # The code is public; the requested value is not echoed back.
            raise UnsupportedLanguageError(log_context={"requested_language_supported": False})

        requested = frozenset(requested_entities) if requested_entities is not None else None

        if not text.strip():
            return []

        target_types = self._config.enabled_entities
        if requested is not None:
            target_types = target_types & requested
        if not target_types:
            return []

        candidates = await asyncio.to_thread(self._analyze, text, language, target_types)

        return finalize(
            candidates,
            text=text,
            config=self._config,
            requested_entities=requested,
            diagnostic=diagnostic,
        )

    def _analyze(
        self,
        text: str,
        language: str,
        target_types: frozenset[str],
    ) -> list[Candidate]:
        """Run the analyzer on a worker thread and adapt its results.

        Presidio's analysis is synchronous and CPU-bound; running it inline
        would stall the event loop for every other in-flight request.
        """
        engine = get_analyzer_engine(self._config)

        # Ask only for types this engine actually supports: an unknown name
        # makes Presidio raise, which would surface as a detector outage.
        available = set(engine.get_supported_entities(language=language))
        entities = sorted(target_types & available)
        if not entities:
            return []

        try:
            results: list[Any] = engine.analyze(text=text, language=language, entities=entities)
        except Exception as exc:  # converted immediately to a safe domain error
            raise DetectorUnavailableError(
                log_context={"stage": "analyze", "reason": type(exc).__name__}
            ) from exc

        return [
            Candidate(
                entity_type=result.entity_type,
                start=result.start,
                end=result.end,
                score=float(result.score),
                recognizer=_recognizer_name(result),
            )
            for result in results
        ]


def _recognizer_name(result: Any) -> str | None:
    """Return the recognizer that produced ``result``, when Presidio reports one."""
    metadata = getattr(result, "recognition_metadata", None)
    if not metadata:
        return None
    name = metadata.get("recognizer_name")
    return str(name) if name else None
