"""The output pipeline's result type.

``RestoredOutput`` is the only place in the system where original values are
back in plaintext after the provider call. It is frozen, it carries no mapping
table, and its ``repr`` omits the text, so an accidental ``repr()`` in a
traceback or a log line cannot leak what was restored.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.domain.models import PrivacySummary, ProviderUsage


@dataclass(frozen=True, slots=True)
class RestoredOutput:
    """Restored provider text plus privacy-safe metadata.

    Return this only to the authenticated principal that made the request. It
    must never be written to an audit row, a log, a metric label, or a trace.
    """

    text: str
    """Provider output with resolvable gateway tokens replaced by originals."""

    summary: PrivacySummary
    """Counts only: ``restored`` and ``unknown_tokens``. Never values."""

    model: str
    """Provider passthrough: the model that actually served the request."""

    usage: ProviderUsage | None = None
    """Provider passthrough. Token accounting, never content."""

    def __repr__(self) -> str:
        # Defensive: the restored text is the most sensitive string in the
        # process. Describe it, never render it.
        return (
            f"RestoredOutput(model={self.model!r}, characters={len(self.text)}, "
            f"restored={self.summary.restored}, "
            f"unknown_tokens={self.summary.unknown_tokens})"
        )
