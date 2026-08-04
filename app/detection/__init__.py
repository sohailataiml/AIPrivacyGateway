"""Sensitive data detection.

Import the Protocol and the fake from here freely: neither pulls in Presidio or
spaCy. :class:`~app.detection.engine.PresidioDetector` does, so it is imported
from its own module rather than re-exported here -- a module that only needs the
seam never pays the model load.

    from app.detection import Detector, FakeDetector          # cheap
    from app.detection.engine import PresidioDetector         # loads spaCy
"""

from __future__ import annotations

from app.detection.base import Detector
from app.detection.checksums import is_valid_credit_card, luhn_is_valid
from app.detection.config import DEFAULT_MAX_ENTITIES, DetectionConfig
from app.detection.entities import (
    DEFAULT_ENTITY_THRESHOLDS,
    DEFAULT_MIN_SCORE,
    ENTITY_PRIORITY,
    SUPPORTED_ENTITY_TYPES,
)
from app.detection.fakes import FakeDetector
from app.detection.overlap import dominance_key, resolve_overlaps
from app.detection.postprocess import Candidate, finalize

__all__ = [
    "DEFAULT_ENTITY_THRESHOLDS",
    "DEFAULT_MAX_ENTITIES",
    "DEFAULT_MIN_SCORE",
    "ENTITY_PRIORITY",
    "SUPPORTED_ENTITY_TYPES",
    "Candidate",
    "DetectionConfig",
    "Detector",
    "FakeDetector",
    "dominance_key",
    "finalize",
    "is_valid_credit_card",
    "luhn_is_valid",
    "resolve_overlaps",
]
