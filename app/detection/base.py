"""The detector seam.

Every consumer -- the pipeline, the ``/v1/detect`` route, tests -- depends on
this Protocol, never on Presidio. That is what lets unit tests run against
:class:`~app.detection.fakes.FakeDetector` without loading a spaCy model.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.domain.models import DetectedEntity


@runtime_checkable
class Detector(Protocol):
    """Finds sensitive spans in text.

    Implementations must fail closed. An empty list means "this text contains
    nothing sensitive"; a detector that cannot do its job raises
    :class:`~app.domain.errors.DetectorUnavailableError` instead, so a caller
    can never confuse a broken engine with clean input.
    """

    async def detect(
        self,
        text: str,
        *,
        language: str = "en",
        requested_entities: set[str] | None = None,
        diagnostic: bool = False,
    ) -> list[DetectedEntity]:
        """Return non-overlapping entities sorted by ``(start, end)``.

        Args:
            text: Text to analyze. Offsets in the result index into this exact
                string -- Python character indices, not bytes.
            language: ISO 639-1 code. v1 supports ``en`` only.
            requested_entities: Restrict the result to these types. ``None``
                means every enabled type.
            diagnostic: When ``True``, populate ``recognizer`` on each result.
                Reserved for privileged callers; never set from a public route.

        Raises:
            UnsupportedLanguageError: ``language`` is not configured.
            EntityLimitExceededError: The text holds more entities than the
                configured maximum.
            DetectorUnavailableError: The engine could not run.
        """
        ...
