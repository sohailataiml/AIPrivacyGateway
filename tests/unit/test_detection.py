"""Detection engine tests.

Split by cost: everything above ``TestPresidioDetector`` is pure Python and
runs in milliseconds. The Presidio class shares one session-scoped engine
because constructing it loads a spaCy model.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from app.detection import (
    Candidate,
    DetectionConfig,
    Detector,
    FakeDetector,
    dominance_key,
    finalize,
    is_valid_credit_card,
    luhn_is_valid,
    resolve_overlaps,
)
from app.detection import analyzer as analyzer_module
from app.detection import engine as engine_module
from app.detection.engine import PresidioDetector
from app.detection.entities import (
    API_KEY,
    CREDIT_CARD,
    DATE_TIME,
    EMAIL_ADDRESS,
    PERSON,
    US_SSN,
)
from app.detection.recognizers import (
    CUSTOM_RECOGNIZER_TYPES,
    ApiKeyRecognizer,
    BearerTokenRecognizer,
    EnterpriseAccountNumberRecognizer,
    HealthPlanIdRecognizer,
    MedicalRecordNumberRecognizer,
)
from app.domain.errors import (
    DetectorUnavailableError,
    EntityLimitExceededError,
    UnsupportedLanguageError,
)
from app.domain.models import DetectedEntity
from tests.fixtures import detection_corpus as corpus


def span(
    entity_type: str,
    start: int,
    end: int,
    score: float = 0.8,
    recognizer: str | None = None,
) -> DetectedEntity:
    """Build a detection by hand, so overlap tests need no detector at all."""
    return DetectedEntity(entity_type, start, end, score, recognizer)


def covered_values(entities: list[DetectedEntity], text: str) -> set[str]:
    return {text[entity.start : entity.end] for entity in entities}


def assert_case_holds(case: corpus.CorpusCase, entities: list[DetectedEntity]) -> None:
    """Assert one corpus case against a detector result."""
    found_types = {entity.entity_type for entity in entities}
    found_values = covered_values(entities, case.text)

    assert case.expected_types <= found_types, case.name
    assert not (case.forbidden_types & found_types), case.name
    for value in case.expected_values:
        assert value in found_values, f"{case.name}: expected {value[:8]}... to be detected"
    for value in case.forbidden_values:
        assert value not in found_values, case.name


class TestLuhnChecksum:
    def test_accepts_a_card_number_with_a_correct_check_digit(self) -> None:
        assert luhn_is_valid(corpus.CARD_LUHN_VALID_PLAIN) is True

    def test_rejects_a_card_number_with_a_wrong_check_digit(self) -> None:
        assert luhn_is_valid(corpus.CARD_LUHN_INVALID_PLAIN) is False

    def test_ignores_separators_when_validating(self) -> None:
        assert luhn_is_valid(corpus.CARD_LUHN_VALID) == luhn_is_valid(corpus.CARD_LUHN_VALID_PLAIN)

    @pytest.mark.parametrize("value", ["", "4", "abcd"])
    def test_rejects_input_with_fewer_than_two_digits(self, value: str) -> None:
        assert luhn_is_valid(value) is False

    @pytest.mark.parametrize("digits", ["4532015112", "45320151128303669999"])
    def test_credit_card_validator_rejects_out_of_range_lengths(self, digits: str) -> None:
        assert is_valid_credit_card(digits) is False


class TestOverlapResolution:
    """The ordering rule, exercised on hand-built spans only."""

    def test_higher_severity_wins_over_higher_confidence(self) -> None:
        # Arrange: a weak SSN and a strong date claim the same characters.
        ssn = span(US_SSN, 0, 11, score=0.55)
        date = span(DATE_TIME, 0, 11, score=0.95)

        # Act
        resolved = resolve_overlaps([date, ssn])

        # Assert
        assert resolved == [ssn]

    def test_higher_confidence_wins_within_the_same_severity(self) -> None:
        weak = span(PERSON, 4, 12, score=0.6)
        strong = span(PERSON, 4, 12, score=0.9)

        resolved = resolve_overlaps([weak, strong])

        assert resolved == [strong]

    def test_longer_span_wins_when_severity_and_confidence_tie(self) -> None:
        short = span(PERSON, 4, 9, score=0.8)
        long = span(PERSON, 4, 14, score=0.8)

        resolved = resolve_overlaps([short, long])

        assert resolved == [long]

    def test_lower_start_offset_wins_when_length_also_ties(self) -> None:
        earlier = span(PERSON, 4, 10, score=0.8)
        later = span(PERSON, 6, 12, score=0.8)

        resolved = resolve_overlaps([later, earlier])

        assert resolved == [earlier]

    def test_entity_type_name_breaks_a_remaining_tie(self) -> None:
        # Same severity tier, same span, same score: only the name differs.
        email = span(EMAIL_ADDRESS, 0, 10, score=0.8)
        phone = span("PHONE_NUMBER", 0, 10, score=0.8)

        resolved = resolve_overlaps([phone, email])

        assert resolved == [email]

    def test_recognizer_name_breaks_the_final_tie(self) -> None:
        first = span(PERSON, 0, 5, score=0.8, recognizer="AlphaRecognizer")
        second = span(PERSON, 0, 5, score=0.8, recognizer="BetaRecognizer")

        resolved = resolve_overlaps([second, first])

        assert resolved == [first]

    def test_result_is_identical_for_every_input_ordering(self) -> None:
        candidates = [
            span(CREDIT_CARD, 5, 24, score=1.0),
            span(DATE_TIME, 5, 24, score=0.85),
            span(EMAIL_ADDRESS, 30, 50, score=1.0),
            span(PERSON, 48, 60, score=0.9),
        ]

        results = {
            tuple(resolve_overlaps(list(ordering)))
            for ordering in itertools.permutations(candidates)
        }

        assert len(results) == 1

    def test_duplicate_spans_collapse_to_a_single_entity(self) -> None:
        duplicate = span(EMAIL_ADDRESS, 0, 20, score=1.0)

        resolved = resolve_overlaps([duplicate, duplicate, duplicate])

        assert resolved == [duplicate]

    def test_non_overlapping_spans_are_all_kept_and_sorted(self) -> None:
        third = span(EMAIL_ADDRESS, 40, 50)
        first = span(PERSON, 0, 5)
        second = span(US_SSN, 10, 21)

        resolved = resolve_overlaps([third, first, second])

        assert resolved == [first, second, third]
        assert [entity.start for entity in resolved] == sorted(e.start for e in resolved)

    def test_adjacent_spans_do_not_count_as_overlapping(self) -> None:
        left = span(PERSON, 0, 10)
        right = span(PERSON, 10, 20)

        assert resolve_overlaps([left, right]) == [left, right]

    def test_chained_overlaps_keep_only_dominant_spans(self) -> None:
        dominant = span(US_SSN, 0, 11, score=0.9)
        middle = span(DATE_TIME, 8, 20, score=0.95)
        trailing = span(PERSON, 19, 30, score=0.5)

        resolved = resolve_overlaps([middle, dominant, trailing])

        assert resolved == [dominant, trailing]

    def test_empty_input_returns_an_empty_list(self) -> None:
        assert resolve_overlaps([]) == []

    def test_input_sequence_is_not_mutated(self) -> None:
        candidates = [span(DATE_TIME, 0, 10, score=0.9), span(US_SSN, 0, 10, score=0.5)]
        snapshot = list(candidates)

        resolve_overlaps(candidates)

        assert candidates == snapshot

    def test_unknown_entity_type_ranks_below_every_known_type(self) -> None:
        known = span(PERSON, 0, 10, score=0.4)
        unknown = span("SOMETHING_NEW", 0, 10, score=0.99)

        assert dominance_key(known) < dominance_key(unknown)
        assert resolve_overlaps([unknown, known]) == [known]


FINALIZE_TEXT = f"Reach me at {corpus.EMAIL} any time."
EMAIL_START = FINALIZE_TEXT.index(corpus.EMAIL)
EMAIL_END = EMAIL_START + len(corpus.EMAIL)


class TestFinalize:
    """Span validation, filtering, and the entity cap."""

    def test_span_beyond_the_end_of_the_text_is_rejected(self) -> None:
        candidates = [Candidate(EMAIL_ADDRESS, 12, len(FINALIZE_TEXT) + 5, 1.0)]

        assert finalize(candidates, text=FINALIZE_TEXT, config=DetectionConfig()) == []

    @pytest.mark.parametrize(("start", "end"), [(-1, 5), (10, 10), (12, 4)])
    def test_malformed_spans_are_rejected(self, start: int, end: int) -> None:
        candidates = [Candidate(EMAIL_ADDRESS, start, end, 1.0)]

        assert finalize(candidates, text=FINALIZE_TEXT, config=DetectionConfig()) == []

    def test_entity_type_outside_the_enabled_set_is_dropped(self) -> None:
        candidates = [Candidate("ORGANIZATION", EMAIL_START, EMAIL_END, 1.0)]

        assert finalize(candidates, text=FINALIZE_TEXT, config=DetectionConfig()) == []

    def test_requested_entities_restricts_the_result(self) -> None:
        candidates = [
            Candidate(EMAIL_ADDRESS, EMAIL_START, EMAIL_END, 1.0),
            Candidate(PERSON, 0, 5, 0.9),
        ]

        resolved = finalize(
            candidates,
            text=FINALIZE_TEXT,
            config=DetectionConfig(),
            requested_entities=frozenset({PERSON}),
        )

        assert [entity.entity_type for entity in resolved] == [PERSON]

    def test_allowlisted_value_is_never_returned(self) -> None:
        config = DetectionConfig().with_allowlist({"jordan.rivera@example.com"})
        candidates = [Candidate(EMAIL_ADDRESS, EMAIL_START, EMAIL_END, 1.0)]

        assert finalize(candidates, text=FINALIZE_TEXT, config=config) == []

    def test_allowlist_matching_ignores_case_and_surrounding_whitespace(self) -> None:
        config = DetectionConfig().with_allowlist({"  JORDAN.RIVERA@EXAMPLE.COM  "})
        candidates = [Candidate(EMAIL_ADDRESS, EMAIL_START, EMAIL_END, 1.0)]

        assert finalize(candidates, text=FINALIZE_TEXT, config=config) == []

    def test_score_below_the_per_entity_threshold_is_dropped(self) -> None:
        candidates = [Candidate(EMAIL_ADDRESS, EMAIL_START, EMAIL_END, 0.45)]

        assert finalize(candidates, text=FINALIZE_TEXT, config=DetectionConfig()) == []

    def test_score_at_the_per_entity_threshold_is_kept(self) -> None:
        candidates = [Candidate(EMAIL_ADDRESS, EMAIL_START, EMAIL_END, 0.5)]

        assert len(finalize(candidates, text=FINALIZE_TEXT, config=DetectionConfig())) == 1

    def test_global_floor_applies_to_a_type_with_no_specific_threshold(self) -> None:
        config = DetectionConfig(entity_thresholds={}, min_score=0.75)
        candidates = [Candidate(EMAIL_ADDRESS, EMAIL_START, EMAIL_END, 0.7)]

        assert finalize(candidates, text=FINALIZE_TEXT, config=config) == []

    def test_card_failing_the_checksum_is_dropped(self) -> None:
        text = f"Card {corpus.CARD_LUHN_INVALID} declined."
        candidates = [Candidate(CREDIT_CARD, 5, 5 + len(corpus.CARD_LUHN_INVALID), 1.0)]

        assert finalize(candidates, text=text, config=DetectionConfig()) == []

    def test_card_passing_the_checksum_is_kept(self) -> None:
        text = f"Card {corpus.CARD_LUHN_VALID} approved."
        candidates = [Candidate(CREDIT_CARD, 5, 5 + len(corpus.CARD_LUHN_VALID), 1.0)]

        assert len(finalize(candidates, text=text, config=DetectionConfig())) == 1

    def test_exceeding_the_entity_limit_raises(self) -> None:
        config = DetectionConfig(max_entities=2)
        candidates = [Candidate(EMAIL_ADDRESS, index * 5, index * 5 + 4, 1.0) for index in range(3)]

        with pytest.raises(EntityLimitExceededError) as excinfo:
            finalize(candidates, text="x" * 100, config=config)

        assert excinfo.value.log_context == {"limit": 2, "detected": 3}

    def test_entity_count_equal_to_the_limit_is_allowed(self) -> None:
        config = DetectionConfig(max_entities=3)
        candidates = [Candidate(EMAIL_ADDRESS, index * 5, index * 5 + 4, 1.0) for index in range(3)]

        assert len(finalize(candidates, text="x" * 100, config=config)) == 3

    def test_recognizer_is_hidden_unless_diagnostic_mode_is_requested(self) -> None:
        candidates = [Candidate(EMAIL_ADDRESS, EMAIL_START, EMAIL_END, 1.0, "EmailRecognizer")]

        default = finalize(candidates, text=FINALIZE_TEXT, config=DetectionConfig())
        diagnostic = finalize(
            candidates, text=FINALIZE_TEXT, config=DetectionConfig(), diagnostic=True
        )

        assert default[0].recognizer is None
        assert diagnostic[0].recognizer == "EmailRecognizer"


class TestDetectionConfig:
    @pytest.mark.parametrize("min_score", [-0.1, 1.5])
    def test_rejects_a_confidence_floor_outside_the_unit_interval(self, min_score: float) -> None:
        with pytest.raises(ValueError, match="min_score"):
            DetectionConfig(min_score=min_score)

    def test_rejects_a_non_positive_entity_limit(self) -> None:
        with pytest.raises(ValueError, match="max_entities"):
            DetectionConfig(max_entities=0)

    def test_rejects_an_empty_language_set(self) -> None:
        with pytest.raises(ValueError, match="language"):
            DetectionConfig(supported_languages=frozenset())

    def test_threshold_never_falls_below_the_global_floor(self) -> None:
        config = DetectionConfig(entity_thresholds={EMAIL_ADDRESS: 0.1}, min_score=0.4)

        assert config.threshold_for(EMAIL_ADDRESS) == 0.4

    def test_with_allowlist_returns_a_copy_and_leaves_the_original_alone(self) -> None:
        original = DetectionConfig()

        derived = original.with_allowlist({"support@example.com"})

        assert original.allowlist == frozenset()
        assert derived.is_allowlisted("SUPPORT@example.com") is True


class TestCustomRecognizers:
    @pytest.mark.parametrize(
        ("recognizer", "text", "expected"),
        [
            (ApiKeyRecognizer(), f"key {corpus.OPENAI_STYLE_KEY}", corpus.OPENAI_STYLE_KEY),
            (ApiKeyRecognizer(), f"id {corpus.AWS_KEY_ID} here", corpus.AWS_KEY_ID),
            (BearerTokenRecognizer(), f"Bearer {corpus.JWT}", corpus.JWT),
            (MedicalRecordNumberRecognizer(), f"chart {corpus.MRN}.", corpus.MRN),
            (HealthPlanIdRecognizer(), f"plan {corpus.HEALTH_PLAN}.", corpus.HEALTH_PLAN),
            (EnterpriseAccountNumberRecognizer(), f"acct {corpus.ACCOUNT}.", corpus.ACCOUNT),
        ],
    )
    def test_sample_format_is_recognized(self, recognizer: Any, text: str, expected: str) -> None:
        results = recognizer.analyze(text, entities=[recognizer.ENTITY])

        assert expected in {text[result.start : result.end] for result in results}

    def test_labelled_secret_reports_the_value_without_its_field_name(self) -> None:
        text = f'"client_secret": "{corpus.OPENAI_STYLE_KEY}"'

        results = ApiKeyRecognizer().analyze(text, entities=[API_KEY])

        assert all(text[result.start : result.end].startswith("sk-") for result in results)

    @pytest.mark.parametrize("placeholder", ["MRN-00000000", "MRN-11111111"])
    def test_placeholder_identifiers_are_not_reported(self, placeholder: str) -> None:
        recognizer = MedicalRecordNumberRecognizer()

        assert recognizer.analyze(f"chart {placeholder}", entities=[recognizer.ENTITY]) == []

    @pytest.mark.parametrize("recognizer_type", CUSTOM_RECOGNIZER_TYPES)
    def test_every_custom_recognizer_declares_context_terms(
        self, recognizer_type: type[Any]
    ) -> None:
        assert recognizer_type.CONTEXT

    def test_recognizer_is_silent_for_entity_types_it_was_not_asked_about(self) -> None:
        recognizer = EnterpriseAccountNumberRecognizer()

        assert recognizer.analyze(f"acct {corpus.ACCOUNT}", entities=[PERSON]) == []


class TestFakeDetector:
    @pytest.mark.parametrize("case", corpus.FAKE_DETECTOR_CASES, ids=lambda c: c.name)
    async def test_corpus_case_detection(self, case: corpus.CorpusCase) -> None:
        detected = await FakeDetector().detect(case.text)

        assert_case_holds(case, detected)

    def test_satisfies_the_detector_protocol(self) -> None:
        assert isinstance(FakeDetector(), Detector)

    async def test_rejects_a_language_the_engine_is_not_configured_for(self) -> None:
        with pytest.raises(UnsupportedLanguageError):
            await FakeDetector().detect("bonjour", language="fr")

    async def test_repeated_runs_return_identical_results(self) -> None:
        detector = FakeDetector()

        first = await detector.detect(corpus.REPEATED_CASE.text)
        second = await detector.detect(corpus.REPEATED_CASE.text)

        assert first == second

    async def test_results_are_sorted_and_non_overlapping(self) -> None:
        detected = await FakeDetector().detect(corpus.ENTERPRISE_IDENTIFIER_CASE.text)

        assert detected == sorted(detected, key=lambda entity: (entity.start, entity.end))
        assert all(left.end <= right.start for left, right in itertools.pairwise(detected))

    async def test_allowlisted_value_is_suppressed(self) -> None:
        detector = FakeDetector(config=DetectionConfig().with_allowlist(corpus.ALLOWLIST_VALUES))

        detected = await detector.detect(corpus.ALLOWLIST_CASE.text)

        assert_case_holds(corpus.ALLOWLIST_CASE, detected)

    async def test_scripted_candidates_replace_the_regex_rules(self) -> None:
        text = "nothing interesting here"
        detector = FakeDetector(scripted={text: [Candidate(PERSON, 0, 7, 0.9)]})

        detected = await detector.detect(text)

        assert detected == [DetectedEntity(PERSON, 0, 7, 0.9)]

    async def test_enforces_the_entity_limit(self) -> None:
        detector = FakeDetector(config=DetectionConfig(max_entities=5))

        with pytest.raises(EntityLimitExceededError):
            await detector.detect(corpus.MAX_ENTITY_CASE.text)

    async def test_reports_the_recognizer_only_in_diagnostic_mode(self) -> None:
        detector = FakeDetector()

        plain = await detector.detect(corpus.EMAIL_CASE.text)
        diagnostic = await detector.detect(corpus.EMAIL_CASE.text, diagnostic=True)

        assert plain[0].recognizer is None
        assert diagnostic[0].recognizer is not None

    async def test_counts_calls_without_retaining_the_analyzed_text(self) -> None:
        detector = FakeDetector()

        await detector.detect(corpus.EMAIL_CASE.text)
        await detector.detect(corpus.SSN_CASE.text)

        assert detector.call_count == 2
        assert corpus.EMAIL not in repr(vars(detector))


class TestDetectorFailureModes:
    """ "Nothing found" and "detector broken" must never look alike."""

    async def test_empty_text_returns_without_touching_the_analyzer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(_: DetectionConfig) -> Any:
            raise AssertionError("the analyzer must not be built for empty text")

        monkeypatch.setattr(engine_module, "get_analyzer_engine", explode)

        assert await PresidioDetector().detect("   \n ") == []

    async def test_unsupported_language_is_rejected_before_the_engine_loads(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(_: DetectionConfig) -> Any:
            raise AssertionError("language validation must come first")

        monkeypatch.setattr(engine_module, "get_analyzer_engine", explode)

        with pytest.raises(UnsupportedLanguageError):
            await PresidioDetector().detect("hola", language="es")

    async def test_analyzer_failure_raises_instead_of_returning_no_entities(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class BrokenEngine:
            def get_supported_entities(self, language: str) -> list[str]:
                return [EMAIL_ADDRESS]

            def analyze(self, **_: object) -> list[object]:
                raise RuntimeError("model unloaded")

        monkeypatch.setattr(engine_module, "get_analyzer_engine", lambda _: BrokenEngine())

        with pytest.raises(DetectorUnavailableError):
            await PresidioDetector().detect(corpus.EMAIL_CASE.text)

    def test_an_unbuildable_model_raises_a_detector_error(self) -> None:
        config = DetectionConfig(spacy_model="en_core_web_model_that_does_not_exist")

        with pytest.raises(DetectorUnavailableError):
            analyzer_module.build_analyzer_engine(config)

    def test_the_engine_is_built_once_and_reused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        builds = 0

        def counting_build(_: DetectionConfig) -> Any:
            nonlocal builds
            builds += 1
            return object()

        monkeypatch.setattr(analyzer_module, "build_analyzer_engine", counting_build)
        analyzer_module.reset_analyzer_cache()
        config = DetectionConfig(spacy_model="cache-probe")

        first = analyzer_module.get_analyzer_engine(config)
        second = analyzer_module.get_analyzer_engine(config)
        analyzer_module.reset_analyzer_cache()

        assert first is second
        assert builds == 1

    def test_a_build_failure_is_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        attempts = 0

        def failing_build(_: DetectionConfig) -> Any:
            nonlocal attempts
            attempts += 1
            raise DetectorUnavailableError()

        monkeypatch.setattr(analyzer_module, "build_analyzer_engine", failing_build)
        analyzer_module.reset_analyzer_cache()
        config = DetectionConfig(spacy_model="failure-probe")

        for _ in range(2):
            with pytest.raises(DetectorUnavailableError):
                analyzer_module.get_analyzer_engine(config)
        analyzer_module.reset_analyzer_cache()

        assert attempts == 2


@pytest.fixture(scope="session")
def presidio_detector() -> PresidioDetector:
    """One detector for the whole session: the spaCy load is the expensive part."""
    return PresidioDetector()


class TestPresidioDetector:
    @pytest.mark.parametrize("case", corpus.ALL_CASES, ids=lambda c: c.name)
    async def test_corpus_case_detection(
        self, presidio_detector: PresidioDetector, case: corpus.CorpusCase
    ) -> None:
        detected = await presidio_detector.detect(case.text)

        assert_case_holds(case, detected)

    def test_satisfies_the_detector_protocol(self) -> None:
        assert isinstance(PresidioDetector(), Detector)

    async def test_results_are_sorted_and_never_overlap(
        self, presidio_detector: PresidioDetector
    ) -> None:
        detected = await presidio_detector.detect(corpus.OVERLAPPING_CASE.text)

        assert detected == sorted(detected, key=lambda entity: (entity.start, entity.end))
        assert all(left.end <= right.start for left, right in itertools.pairwise(detected))

    async def test_offsets_index_the_original_unicode_string(
        self, presidio_detector: PresidioDetector
    ) -> None:
        case = corpus.UNICODE_CASE

        detected = await presidio_detector.detect(case.text)

        assert corpus.EMAIL in covered_values(detected, case.text)

    async def test_repeated_values_are_reported_at_every_offset(
        self, presidio_detector: PresidioDetector
    ) -> None:
        detected = await presidio_detector.detect(corpus.REPEATED_CASE.text)

        assert len([e for e in detected if e.entity_type == EMAIL_ADDRESS]) == 3

    async def test_allowlisted_value_is_suppressed(self) -> None:
        detector = PresidioDetector(DetectionConfig().with_allowlist(corpus.ALLOWLIST_VALUES))

        detected = await detector.detect(corpus.ALLOWLIST_CASE.text)

        assert_case_holds(corpus.ALLOWLIST_CASE, detected)

    async def test_requested_entities_restricts_the_result(
        self, presidio_detector: PresidioDetector
    ) -> None:
        case = corpus.NAME_AND_LOCATION_CASE

        detected = await presidio_detector.detect(case.text, requested_entities={PERSON})

        assert {entity.entity_type for entity in detected} == {PERSON}

    async def test_an_unknown_requested_entity_yields_nothing(
        self, presidio_detector: PresidioDetector
    ) -> None:
        detected = await presidio_detector.detect(
            corpus.EMAIL_CASE.text, requested_entities={"NOT_A_REAL_TYPE"}
        )

        assert detected == []

    async def test_recognizer_names_appear_only_in_diagnostic_mode(
        self, presidio_detector: PresidioDetector
    ) -> None:
        text = corpus.SSN_CASE.text

        plain = await presidio_detector.detect(text)
        diagnostic = await presidio_detector.detect(text, diagnostic=True)

        assert all(entity.recognizer is None for entity in plain)
        assert any(entity.recognizer for entity in diagnostic)

    async def test_a_number_failing_the_checksum_is_not_a_credit_card(
        self, presidio_detector: PresidioDetector
    ) -> None:
        detected = await presidio_detector.detect(corpus.CREDIT_CARD_INVALID_CASE.text)

        assert CREDIT_CARD not in {entity.entity_type for entity in detected}

    async def test_context_words_raise_confidence_for_an_ambiguous_identifier(
        self, presidio_detector: PresidioDetector
    ) -> None:
        # The same nine digits, once beside its context words and once alone.
        with_context = await presidio_detector.detect(corpus.SSN_CASE.text)
        bare = await presidio_detector.detect(f"The number on the form is {corpus.SSN} exactly.")

        with_score = next(e.score for e in with_context if e.entity_type == US_SSN)
        bare_score = next(e.score for e in bare if e.entity_type == US_SSN)
        assert with_score > bare_score

    async def test_exceeding_the_entity_limit_raises(self) -> None:
        detector = PresidioDetector(DetectionConfig(max_entities=5))

        with pytest.raises(EntityLimitExceededError):
            await detector.detect(corpus.MAX_ENTITY_CASE.text)

    async def test_warm_up_makes_the_engine_available(
        self, presidio_detector: PresidioDetector
    ) -> None:
        await presidio_detector.warm_up()

        assert await presidio_detector.detect(corpus.EMAIL_CASE.text)
