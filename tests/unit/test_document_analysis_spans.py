"""The span algebra, and the invariants the next phase is allowed to assume.

Everything under test here is pure, which is the point: given the same
detections and the same policy, a document must protect the same characters on
every run and every machine. So most of these are universal claims and are
tested as such, with Hypothesis generating the inputs.

Two are load-bearing.

``test_a_value_straddling_a_boundary_is_labeled_once_and_whole`` is the reason
this module exists. Segmentation guarantees an entity shorter than the overlap
appears whole in *some* segment; that guarantee is worth nothing if the merge
step then reports the whole value and a fragment of it as two separate spans, or
picks the fragment. Either outcome protects the wrong characters while every
count says the document was handled.

``TestAnalyzedDocumentInvariants`` asserts what construction refuses. An
``AnalyzedDocument`` is the checkpoint the protection phase trusts instead of
re-validating, so each invariant it claims needs a test proving it is not merely
documented.
"""

from __future__ import annotations

import itertools
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.detection.entities import (
    API_KEY,
    CREDIT_CARD,
    DATE_TIME,
    EMAIL_ADDRESS,
    PERSON,
    US_SSN,
)
from app.documents.analysis.models import AnalyzedDocument, LabeledSpan
from app.documents.analysis.spans import (
    GlobalDetection,
    blocked_entity_type,
    coalesce,
    label,
    resolve,
    select_confident,
    to_global,
)
from app.documents.extraction.models import build_extracted_document
from app.documents.segmentation import Segmenter
from app.domain.errors import DocumentExtractionError
from app.domain.models import DetectedEntity, EntityAction
from app.policy.models import EntityRule, PolicySnapshot
from tests.fixtures.policies import snapshot

if TYPE_CHECKING:
    from collections.abc import Mapping

    from app.documents.segmentation import Segment, SegmentedDocument

TENANT = UUID("11111111-1111-1111-1111-111111111111")
DOCUMENT = UUID("55555555-5555-5555-5555-555555555555")

TOKENIZE_EVERYTHING = {
    PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    US_SSN: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
    DATE_TIME: EntityRule(action=EntityAction.ALLOW, min_score=0.5),
}


def policy(
    entities: Mapping[str, EntityRule] | None = None,
    *,
    version: int = 7,
    max_entities: int = 500,
) -> PolicySnapshot:
    return snapshot(
        entities if entities is not None else TOKENIZE_EVERYTHING,
        tenant_id=TENANT,
        version=version,
        max_entities=max_entities,
    )


def detection(
    entity_type: str,
    start: int,
    end: int,
    score: float = 0.9,
    segments: tuple[int, ...] = (0,),
) -> GlobalDetection:
    return GlobalDetection(
        entity=DetectedEntity(entity_type=entity_type, start=start, end=end, score=score),
        segments=segments,
    )


def segmented_of(text: str, *, max_characters: int, overlap: int) -> SegmentedDocument:
    return Segmenter(max_characters=max_characters, overlap_characters=overlap).segment(
        build_extracted_document(page_texts=[text])
    )


# ---------------------------------------------------------------------------
# Promoting segment offsets to document offsets
# ---------------------------------------------------------------------------
class TestToGlobal:
    def test_offsets_are_rewritten_against_the_document(self) -> None:
        # Arrange -- a value that lands in the second segment, so its local and
        # global offsets genuinely differ. A test built on segment 0 would pass
        # against an implementation that ignored the segment entirely.
        text = "x" * 150 + "jordan@example.test" + "y" * 150
        segmented = segmented_of(text, max_characters=100, overlap=32)
        target = next(
            segment
            for segment in segmented.segments
            if "jordan@example.test" in segmented.text_of(segment)
        )
        local = segmented.text_of(target).index("jordan@example.test")

        # Act
        promoted = to_global(
            target,
            [
                DetectedEntity(
                    entity_type=EMAIL_ADDRESS,
                    start=local,
                    end=local + len("jordan@example.test"),
                    score=0.9,
                )
            ],
        )

        # Assert
        assert len(promoted) == 1
        span = promoted[0].entity
        assert text[span.start : span.end] == "jordan@example.test"
        assert promoted[0].segments == (target.index,)

    def test_the_recognizer_name_never_travels_with_a_document_span(self) -> None:
        # Diagnostic output is for a privileged caller inspecting one prompt.
        # There is no document path that wants it, so it is dropped rather than
        # carried and hopefully-not-serialized later.
        segmented = segmented_of("a" * 50, max_characters=100, overlap=0)

        promoted = to_global(
            segmented.segments[0],
            [DetectedEntity(PERSON, 0, 5, 0.9, recognizer="SpacyRecognizer")],
        )

        assert promoted[0].entity.recognizer is None

    def test_an_offset_outside_the_segment_is_refused(self) -> None:
        # The detector's own post-processing already rejects these. This is the
        # backstop for a Detector implementation that does not.
        segmented = segmented_of("a" * 50, max_characters=100, overlap=0)
        segment = segmented.segments[0]

        with pytest.raises(DocumentExtractionError):
            to_global(segment, [DetectedEntity(PERSON, 0, segment.length + 1, 0.9)])


# ---------------------------------------------------------------------------
# Collapsing the duplicates segmentation creates on purpose
# ---------------------------------------------------------------------------
class TestCoalesce:
    def test_the_same_span_from_two_segments_becomes_one(self) -> None:
        merged = coalesce(
            [
                detection(EMAIL_ADDRESS, 100, 120, score=0.8, segments=(3,)),
                detection(EMAIL_ADDRESS, 100, 120, score=0.9, segments=(4,)),
            ]
        )

        assert len(merged) == 1
        assert merged[0].segments == (3, 4)

    def test_the_higher_score_survives(self) -> None:
        # Segmentation cuts context, and Presidio scores by the words around a
        # match, so the segment that saw the value intact is the one that scored
        # it correctly. Taking the maximum can only move a span *over* a policy
        # threshold, never under one.
        merged = coalesce(
            [
                detection(PERSON, 10, 20, score=0.55, segments=(0,)),
                detection(PERSON, 10, 20, score=0.95, segments=(1,)),
            ]
        )

        assert merged[0].entity.score == pytest.approx(0.95)

    def test_different_types_over_the_same_range_are_not_merged(self) -> None:
        # These genuinely disagree about what the characters are. Merging them
        # would silently pick one; resolution is where that choice belongs, and
        # it has a documented ordering rule.
        merged = coalesce(
            [detection(US_SSN, 10, 21, score=0.6), detection(DATE_TIME, 10, 21, score=0.9)]
        )

        assert len(merged) == 2

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(
        spans=st.lists(
            st.tuples(
                st.sampled_from([PERSON, EMAIL_ADDRESS, US_SSN]),
                st.integers(min_value=0, max_value=200),
                st.integers(min_value=1, max_value=40),
                st.floats(min_value=0.5, max_value=1.0),
                st.integers(min_value=0, max_value=9),
            ),
            max_size=40,
        )
    )
    def test_coalescing_is_order_independent_and_idempotent(
        self, spans: list[tuple[str, int, int, float, int]]
    ) -> None:
        detections = [
            detection(entity_type, start, start + length, score, (segment,))
            for entity_type, start, length, score, segment in spans
        ]

        forward = coalesce(detections)
        backward = coalesce(reversed(detections))

        assert forward == backward, "the result must not depend on input order"
        assert coalesce(forward) == forward, "coalescing twice must change nothing"


# ---------------------------------------------------------------------------
# Confidence, and why it is applied before overlap resolution
# ---------------------------------------------------------------------------
class TestSelectConfident:
    def test_a_span_below_its_type_threshold_is_dropped(self) -> None:
        strict = policy({PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.8)})

        kept = select_confident([detection(PERSON, 0, 10, score=0.75)], policy=strict)

        assert kept == []

    def test_an_unconfigured_type_survives_on_the_protective_default(self) -> None:
        # UNKNOWN_ENTITY_MIN_SCORE is 0.0 on purpose: if the detector was
        # confident enough to report a type the policy never mentions, the safe
        # response is to act on it rather than discard it.
        narrow = policy({PERSON: EntityRule(action=EntityAction.TOKENIZE, min_score=0.9)})

        kept = select_confident([detection(CREDIT_CARD, 0, 16, score=0.5)], policy=narrow)

        assert len(kept) == 1

    def test_filtering_first_keeps_the_value_that_resolving_first_would_lose(self) -> None:
        # The reason for the stage order, stated as a test.
        #
        # A sub-threshold API_KEY overlapping an above-threshold EMAIL_ADDRESS.
        # API_KEY is SEVERITY_CRITICAL and EMAIL_ADDRESS is SEVERITY_MEDIUM, and
        # severity is the *first* key of the ordering rule -- so resolving first
        # lets the api key take the span and then be dropped for confidence,
        # leaving nothing protecting those characters at all. Filtering first
        # lets the address survive and be tokenized.
        rules = policy(
            {
                API_KEY: EntityRule(action=EntityAction.TOKENIZE, min_score=0.8),
                EMAIL_ADDRESS: EntityRule(action=EntityAction.TOKENIZE, min_score=0.5),
            }
        )
        detections = [
            detection(API_KEY, 10, 30, score=0.6),
            detection(EMAIL_ADDRESS, 12, 32, score=0.7),
        ]

        as_built = resolve(select_confident(coalesce(detections), policy=rules))
        reversed_order = select_confident(resolve(coalesce(detections)), policy=rules)

        assert [item.entity.entity_type for item in as_built] == [EMAIL_ADDRESS]
        assert reversed_order == [], "the wrong order protects nothing at all"


# ---------------------------------------------------------------------------
# Resolution across the whole document
# ---------------------------------------------------------------------------
class TestResolve:
    def test_overlapping_spans_collapse_to_one_interpretation(self) -> None:
        resolved = resolve(
            coalesce(
                [detection(US_SSN, 10, 21, score=0.9), detection(DATE_TIME, 14, 24, score=0.9)]
            )
        )

        assert len(resolved) == 1
        assert resolved[0].entity.entity_type == US_SSN, "severity decides, per architecture 9.4"

    def test_provenance_survives_resolution(self) -> None:
        # A span that won still has to know which segments it came from, or the
        # merge that produced it cannot be explained afterwards.
        resolved = resolve(
            coalesce(
                [
                    detection(US_SSN, 10, 21, score=0.7, segments=(2,)),
                    detection(US_SSN, 10, 21, score=0.9, segments=(3,)),
                ]
            )
        )

        assert resolved[0].segments == (2, 3)

    def test_adjacent_spans_both_survive(self) -> None:
        resolved = resolve(coalesce([detection(PERSON, 0, 10), detection(EMAIL_ADDRESS, 10, 30)]))

        assert len(resolved) == 2

    def test_the_result_is_ordered_and_non_overlapping(self) -> None:
        resolved = resolve(
            coalesce(
                [
                    detection(EMAIL_ADDRESS, 50, 70),
                    detection(PERSON, 0, 10),
                    detection(US_SSN, 20, 31),
                ]
            )
        )

        for previous, following in itertools.pairwise(resolved):
            assert previous.entity.end <= following.entity.start


# ---------------------------------------------------------------------------
# Blocking
# ---------------------------------------------------------------------------
class TestBlocking:
    def test_a_blocked_type_is_reported_by_name(self) -> None:
        rules = policy({US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5)})

        assert blocked_entity_type([detection(US_SSN, 0, 11)], policy=rules) == US_SSN

    def test_nothing_blocked_reports_none(self) -> None:
        assert blocked_entity_type([detection(PERSON, 0, 10)], policy=policy()) is None

    def test_a_blocked_span_cannot_be_labeled(self) -> None:
        # Belt and braces: the analyzer refuses the document before labelling,
        # and LabeledSpan refuses to represent a block even if it did not.
        rules = policy({US_SSN: EntityRule(action=EntityAction.BLOCK, min_score=0.5)})
        document = build_extracted_document(page_texts=["x" * 50])

        with pytest.raises(ValueError, match="blocked"):
            label([detection(US_SSN, 0, 11)], document=document, policy=rules)


# ---------------------------------------------------------------------------
# Labelling
# ---------------------------------------------------------------------------
class TestLabel:
    def test_the_policy_action_lands_on_the_span(self) -> None:
        rules = policy(
            {
                PERSON: EntityRule(action=EntityAction.PSEUDONYMIZE, min_score=0.5),
                DATE_TIME: EntityRule(action=EntityAction.ALLOW, min_score=0.5),
            }
        )
        document = build_extracted_document(page_texts=["x" * 60])

        labeled = label(
            [detection(PERSON, 0, 10), detection(DATE_TIME, 20, 30)],
            document=document,
            policy=rules,
        )

        assert [span.action for span in labeled] == [
            EntityAction.PSEUDONYMIZE,
            EntityAction.ALLOW,
        ]

    def test_an_unconfigured_type_gets_the_protective_default(self) -> None:
        # A detector can emit a new type well before an operator lists it.
        # Defaulting to ALLOW would ship it to the provider in the clear.
        rules = policy({PERSON: EntityRule(action=EntityAction.ALLOW, min_score=0.5)})
        document = build_extracted_document(page_texts=["x" * 60])

        labeled = label([detection(CREDIT_CARD, 0, 16)], document=document, policy=rules)

        assert labeled[0].action is EntityAction.TOKENIZE

    def test_page_references_are_attached(self) -> None:
        document = build_extracted_document(page_texts=["a" * 40, "b" * 40, "c" * 40])

        labeled = label([detection(PERSON, 45, 55)], document=document, policy=policy())

        assert labeled[0].pages == (2,)

    def test_a_span_crossing_a_page_break_names_both_pages(self) -> None:
        document = build_extracted_document(page_texts=["a" * 40, "b" * 40])

        labeled = label([detection(PERSON, 38, 44)], document=document, policy=policy())

        assert labeled[0].pages == (1, 2)


# ---------------------------------------------------------------------------
# The fail-open property this whole phase exists to avoid
# ---------------------------------------------------------------------------
class TestBoundaryValues:
    @pytest.mark.parametrize("offset", list(range(80, 140)))
    def test_a_value_straddling_a_boundary_is_labeled_once_and_whole(self, offset: int) -> None:
        # Arrange -- a distinctive value slid across the region where a segment
        # boundary falls, and a detector that reports every occurrence it finds
        # in whatever segment it is given. Segmentation guarantees the value
        # appears whole in at least one segment; this asserts the merge does not
        # then squander that by reporting the whole value *and* a fragment, or
        # by preferring the fragment.
        value = "451-88-7396"
        filler = "word " * 80
        text = filler[:offset] + value + filler[offset:]
        segmented = segmented_of(text, max_characters=100, overlap=32)

        # Act -- every whole occurrence, plus every partial one a segment can
        # see, which is exactly what a real recognizer produces after a cut.
        detections: list[GlobalDetection] = []
        for segment in segmented.segments:
            piece = segmented.text_of(segment)
            for found in _occurrences(piece, value):
                detections.append(_local(segment, US_SSN, found, found + len(value), 0.9))
            for fragment in _fragments(piece, value):
                detections.append(_local(segment, US_SSN, *fragment, 0.9))

        labeled = label(
            resolve(select_confident(coalesce(detections), policy=policy())),
            document=segmented.document,
            policy=policy(),
        )

        # Assert
        covering = [span for span in labeled if text[span.start : span.end] == value]
        assert len(covering) == 1, f"{value!r} at offset {offset} produced {len(covering)} spans"
        touching = [
            span
            for span in labeled
            if span.start < text.index(value) + len(value) and span.end > text.index(value)
        ]
        assert touching == covering, "a fragment survived alongside the whole value"

    def test_two_detections_of_one_value_never_become_two_spans(self) -> None:
        # The overlap region, minimally. Both segments see the same email at the
        # same global offsets, and exactly one span comes out.
        text = "x" * 90 + "jordan@example.test" + "y" * 90
        segmented = segmented_of(text, max_characters=120, overlap=64)
        start = text.index("jordan@example.test")
        end = start + len("jordan@example.test")

        seen = [
            segment
            for segment in segmented.segments
            if segment.start <= start and end <= segment.end
        ]
        detections = [
            _local(segment, EMAIL_ADDRESS, start - segment.start, end - segment.start, 0.9)
            for segment in seen
        ]

        labeled = label(
            resolve(select_confident(coalesce(detections), policy=policy())),
            document=segmented.document,
            policy=policy(),
        )

        assert len(seen) >= 2, "the fixture must actually put the value in two segments"
        assert len(labeled) == 1
        assert labeled[0].segments == tuple(segment.index for segment in seen)


def _local(
    segment: Segment, entity_type: str, start: int, end: int, score: float
) -> GlobalDetection:
    return to_global(
        segment,
        [DetectedEntity(entity_type=entity_type, start=start, end=end, score=score)],
    )[0]


def _occurrences(text: str, value: str) -> list[int]:
    found: list[int] = []
    index = text.find(value)
    while index != -1:
        found.append(index)
        index = text.find(value, index + 1)
    return found


def _fragments(text: str, value: str) -> list[tuple[int, int]]:
    """Partial matches a recognizer would see where a cut split the value.

    A prefix of the value at the end of the segment, or a suffix at the start.
    These are what make the merge step load-bearing: a fragment surviving next
    to the whole value means two spans for one entity.
    """
    pieces: list[tuple[int, int]] = []
    for size in range(4, len(value)):
        if text.endswith(value[:size]):
            pieces.append((len(text) - size, len(text)))
        if text.startswith(value[-size:]):
            pieces.append((0, size))
    return pieces


# ---------------------------------------------------------------------------
# What the checkpoint type refuses
# ---------------------------------------------------------------------------
class TestLabeledSpanInvariants:
    @pytest.mark.parametrize(
        ("start", "end"),
        [(-1, 5), (5, 5), (5, 4)],
    )
    def test_an_empty_or_backwards_range_is_unconstructable(self, start: int, end: int) -> None:
        with pytest.raises(ValueError, match="forward range"):
            LabeledSpan(
                entity_type=PERSON,
                start=start,
                end=end,
                score=0.9,
                action=EntityAction.TOKENIZE,
                pages=(1,),
                segments=(0,),
            )

    @pytest.mark.parametrize("score", [-0.1, 1.1])
    def test_a_score_outside_the_unit_interval_is_unconstructable(self, score: float) -> None:
        with pytest.raises(ValueError, match="score"):
            LabeledSpan(
                entity_type=PERSON,
                start=0,
                end=5,
                score=score,
                action=EntityAction.TOKENIZE,
                pages=(1,),
                segments=(0,),
            )

    def test_a_span_with_no_page_or_no_segment_is_unconstructable(self) -> None:
        # A span that cannot say where it came from cannot be traced in an audit
        # trail, which is most of what a page reference is for.
        with pytest.raises(ValueError, match="page"):
            LabeledSpan(PERSON, 0, 5, 0.9, EntityAction.TOKENIZE, (), (0,))
        with pytest.raises(ValueError, match="segment"):
            LabeledSpan(PERSON, 0, 5, 0.9, EntityAction.TOKENIZE, (1,), ())

    def test_length_is_the_span_width(self) -> None:
        span = LabeledSpan(US_SSN, 40, 51, 0.9, EntityAction.TOKENIZE, (1,), (0,))

        assert span.length == 11

    def test_block_is_unrepresentable(self) -> None:
        with pytest.raises(ValueError, match="blocked"):
            LabeledSpan(US_SSN, 0, 11, 0.9, EntityAction.BLOCK, (1,), (0,))


class TestAnalyzedDocumentInvariants:
    def _document(
        self, spans: tuple[LabeledSpan, ...], *, text: str = "x" * 200
    ) -> AnalyzedDocument:
        return AnalyzedDocument(
            tenant_id=TENANT,
            document_id=DOCUMENT,
            segmented=segmented_of(text, max_characters=1_000, overlap=0),
            spans=spans,
            policy=policy(),
        )

    def _span(self, start: int, end: int, entity_type: str = PERSON) -> LabeledSpan:
        return LabeledSpan(
            entity_type=entity_type,
            start=start,
            end=end,
            score=0.9,
            action=EntityAction.TOKENIZE,
            pages=(1,),
            segments=(0,),
        )

    def test_overlapping_spans_are_unconstructable(self) -> None:
        # The protection phase splices right to left over these. Two spans that
        # overlap mean one splice corrupts the other's offsets, so the wrong
        # characters are replaced while every count reports success.
        with pytest.raises(ValueError, match="overlaps"):
            self._document((self._span(10, 30), self._span(20, 40)))

    def test_out_of_order_spans_are_unconstructable(self) -> None:
        with pytest.raises(ValueError, match="overlaps or precedes"):
            self._document((self._span(50, 60), self._span(10, 20)))

    def test_a_span_past_the_end_of_the_text_is_unconstructable(self) -> None:
        with pytest.raises(ValueError, match="past the end"):
            self._document((self._span(190, 260),))

    def test_adjacent_spans_are_allowed(self) -> None:
        analyzed = self._document((self._span(10, 20), self._span(20, 30)))

        assert analyzed.span_count == 2

    def test_no_spans_is_a_valid_document(self) -> None:
        # A clean document is a real outcome, not an error. Refusing it would
        # make "nothing sensitive found" indistinguishable from a failure.
        analyzed = self._document(())

        assert analyzed.span_count == 0
        assert analyzed.counts_by_action() == {}

    def test_counts_are_derived_from_the_spans(self) -> None:
        analyzed = self._document(
            (
                self._span(0, 10, PERSON),
                self._span(20, 40, EMAIL_ADDRESS),
                self._span(50, 60, PERSON),
            )
        )

        assert analyzed.counts_by_entity_type() == {PERSON: 2, EMAIL_ADDRESS: 1}
        assert analyzed.counts_by_action() == {EntityAction.TOKENIZE: 3}

    def test_text_of_reads_the_one_canonical_buffer(self) -> None:
        analyzed = self._document((self._span(0, 5),), text="hello world" + "x" * 100)

        assert analyzed.text_of(analyzed.spans[0]) == "hello"

    def test_the_repr_hides_the_document(self) -> None:
        analyzed = self._document((self._span(0, 5),), text="Marguerite Okonkwo-Vasquez" + "x" * 80)

        assert "Marguerite" not in repr(analyzed)
        assert "spans=1" in repr(analyzed)
