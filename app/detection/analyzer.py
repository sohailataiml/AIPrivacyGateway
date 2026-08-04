"""Construction and caching of the Presidio ``AnalyzerEngine``.

Building an engine loads a spaCy pipeline: seconds of CPU and hundreds of
megabytes of resident memory. It happens at most once per (model, languages)
pair for the life of the process, guarded by a lock so two concurrent first
requests cannot both pay for it.

The engine is configured explicitly rather than by ``AnalyzerEngine()``
defaults. The default constructor resolves its NLP model and its recognizer
registry from packaged configuration files, which means a Presidio upgrade, a
missing model, or a stray ``default.yaml`` on the path silently changes which
entity types the gateway can see. Naming the model and loading the registry
here makes that a startup failure instead of a privacy regression.
"""

from __future__ import annotations

import threading
from typing import Any

from app.detection.config import DetectionConfig
from app.detection.recognizers import build_custom_recognizers
from app.domain.errors import DetectorUnavailableError

_EngineKey = tuple[str, tuple[str, ...]]

_engine_cache: dict[_EngineKey, Any] = {}
_engine_lock = threading.Lock()


def _cache_key(config: DetectionConfig) -> _EngineKey:
    return (config.spacy_model, tuple(sorted(config.supported_languages)))


def build_analyzer_engine(config: DetectionConfig) -> Any:
    """Construct a fully configured ``AnalyzerEngine``. Never cached here.

    Raises:
        DetectorUnavailableError: The spaCy model or the registry could not be
            loaded. The public message names no path and no component version.
    """
    languages = sorted(config.supported_languages)
    try:
        # Imported lazily: importing presidio pulls in spaCy, and modules that
        # only need the Protocol or the fake must not pay for that.
        import spacy.util
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Presidio's spaCy engine downloads a missing model on the spot. A
        # gateway must never reach the network mid-request, and a silent
        # download would mask a broken deployment, so absence is an outage.
        if config.spacy_model not in spacy.util.get_installed_models():
            raise DetectorUnavailableError(log_context={"stage": "model_missing"})

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [
                    {"lang_code": language, "model_name": config.spacy_model}
                    for language in languages
                ],
            }
        )
        nlp_engine = provider.create_engine()

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(languages=languages, nlp_engine=nlp_engine)
        for language in languages:
            for recognizer in build_custom_recognizers(language):
                registry.add_recognizer(recognizer)

        return AnalyzerEngine(
            nlp_engine=nlp_engine,
            registry=registry,
            supported_languages=languages,
            default_score_threshold=0.0,
            log_decision_process=False,
        )
    except DetectorUnavailableError:
        raise
    except Exception as exc:  # converted immediately to a safe domain error
        raise DetectorUnavailableError(
            log_context={"stage": "analyzer_build", "reason": type(exc).__name__}
        ) from exc


def get_analyzer_engine(config: DetectionConfig) -> Any:
    """Return the process-wide engine for ``config``, building it on first use.

    Failures are not cached: a transient problem during startup must not
    poison every later request.
    """
    key = _cache_key(config)
    cached = _engine_cache.get(key)
    if cached is not None:
        return cached

    with _engine_lock:
        # Re-check: another thread may have built it while we waited.
        cached = _engine_cache.get(key)
        if cached is not None:
            return cached
        engine = build_analyzer_engine(config)
        _engine_cache[key] = engine
        return engine


def reset_analyzer_cache() -> None:
    """Drop every cached engine. Test-support only."""
    with _engine_lock:
        _engine_cache.clear()
