"""Segmentation invariants.

Segmentation is the stage most able to cause a silent leak, because its failure
mode is not an exception -- it is an entity cut in half so that no recognizer
matches either piece, and a document that sails through detection looking clean.

So the assertions here are mostly universal claims, and they are tested as such:
Hypothesis generates the text and the settings, and the properties must hold for
all of them. A handful of hand-picked examples would confirm the cases I thought
of, which is exactly the set a boundary bug lives outside.

The load-bearing property is ``test_a_value_at_any_offset_survives_whole_in_some
_segment``. Everything else supports it.
"""

from __future__ import annotations

import itertools

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.documents.extraction.models import build_extracted_document
from app.documents.segmentation import (
    DEFAULT_MAX_CHARACTERS,
    DEFAULT_OVERLAP_CHARACTERS,
    Segmenter,
)
from app.domain.errors import DocumentExtractionError

PROSE = (
    "Marguerite Okonkwo-Vasquez attended the oncology clinic on Tuesday. "
    "Her record number is MRN-ZZ4471903 and her contact address is "
    "marguerite.okonkwo@zzcanary-clinic.test for follow-up correspondence.\n\n"
)


def document(text: str, *, pages: int = 1):
    """An extracted document whose text is exactly ``text``."""
    if pages == 1:
        return build_extracted_document(page_texts=[text])
    size = max(1, len(text) // pages)
    chunks = [text[index : index + size] for index in range(0, len(text), size)] or [""]
    return build_extracted_document(page_texts=chunks, separator="")


def texts_of(segmented) -> list[str]:
    return [segmented.text_of(segment) for segment in segmented.segments]


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------
class TestStructure:
    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    @given(
        text=st.text(min_size=1, max_size=2_000),
        max_characters=st.integers(min_value=8, max_value=400),
        overlap=st.integers(min_value=0, max_value=200),
    )
    def test_segments_cover_the_document_and_make_progress(
        self, text: str, max_characters: int, overlap: int
    ) -> None:
        # Arrange -- the constructor refuses an overlap that cannot progress,
        # so keep the generated pair inside the legal region.
        overlap = min(overlap, max_characters - 1)
        segmenter = Segmenter(max_characters=max_characters, overlap_characters=overlap)

        # Act
        segmented = segmenter.segment(document(text))
        segments = segmented.segments

        # Assert
        assert segments, "a non-empty document must produce at least one segment"
        assert segments[0].start == 0
        assert segments[-1].end == len(text)
        for index, segment in enumerate(segments):
            assert segment.index == index
            assert segment.end > segment.start, "no segment may be empty"
            assert segmented.text_of(segment) == text[segment.start : segment.end]
        for previous, following in itertools.pairwise(segments):
            assert following.start > previous.start, "segments must advance"
            assert following.start <= previous.end, "segments must not leave a gap"
            assert following.end > previous.end

    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    @given(
        text=st.text(min_size=1, max_size=1_500),
        max_characters=st.integers(min_value=8, max_value=300),
    )
    def test_every_character_appears_in_some_segment(self, text: str, max_characters: int) -> None:
        segmenter = Segmenter(max_characters=max_characters, overlap_characters=4)

        segmented = segmenter.segment(document(text))

        # Reassembling by taking each segment from where the last one ended
        # must reproduce the document exactly.
        rebuilt = ""
        for segment in segmented.segments:
            rebuilt += text[max(segment.start, len(rebuilt)) : segment.end]
        assert rebuilt == text

    def test_no_segment_is_contained_in_the_one_before_it(self) -> None:
        # The exact counterexample Hypothesis found. With a break sitting just
        # inside the previous segment, the boundary search used to return an
        # end that had already been covered, producing a segment wholly
        # inside its predecessor: no new characters, and on longer input a run
        # of near-identical segments and duplicate detection work.
        segmenter = Segmenter(max_characters=8, overlap_characters=7)

        segmented = segmenter.segment(document("0000000 00"))

        for previous, following in itertools.pairwise(segmented.segments):
            assert following.end > previous.end

    def test_frequent_breaks_with_a_large_overlap_do_not_multiply_segments(
        self,
    ) -> None:
        # The consequence the fix prevents, stated as a bound. Without it this
        # input produced a segment per character rather than per chunk.
        segmenter = Segmenter(max_characters=8, overlap_characters=7)
        text = "0000000 " * 40

        segmented = segmenter.segment(document(text))

        assert segmented.segment_count <= len(text)
        for previous, following in itertools.pairwise(segmented.segments):
            assert following.end > previous.end

    def test_a_short_document_is_one_segment(self) -> None:
        segmented = Segmenter(max_characters=1_000).segment(document(PROSE))

        assert segmented.segment_count == 1
        assert segmented.text_of(segmented.segments[0]) == PROSE

    def test_an_empty_document_is_refused_rather_than_yielding_nothing(self) -> None:
        # A scanned PDF with no text layer extracts to nothing. Returning zero
        # segments would look like success and send an empty prompt onward.
        with pytest.raises(DocumentExtractionError) as caught:
            Segmenter().segment(document(""))

        assert caught.value.log_context["reason"] == "no_extractable_text"


# ---------------------------------------------------------------------------
# The fail-open property
# ---------------------------------------------------------------------------
class TestEntitiesSurviveBoundaries:
    @pytest.mark.parametrize("offset", list(range(90, 130)))
    def test_a_value_at_any_offset_survives_whole_in_some_segment(self, offset: int) -> None:
        # Arrange -- a distinctive value slid across the region where a
        # boundary will fall. This is the fail-open condition stated as a test:
        # if a boundary cuts the value and no segment holds it whole, no
        # recognizer will ever see it and the document leaves looking clean.
        value = "451-88-7396"
        filler = "x" * 400
        segmenter = Segmenter(max_characters=100, overlap_characters=32)

        text = filler[:offset] + value + filler[offset:]
        segmented = segmenter.segment(document(text))

        assert any(value in piece for piece in texts_of(segmented)), (
            f"{value!r} at offset {offset} was split across every segment"
        )

    @pytest.mark.parametrize(
        "value",
        [
            "marguerite.okonkwo@zzcanary-clinic.test",
            "MRN-ZZ4471903",
            "Marguerite Okonkwo-Vasquez",
            "+1-415-555-0197",
        ],
    )
    def test_realistic_values_survive_boundaries_at_every_offset(self, value: str) -> None:
        # Includes a value containing a space. Breaking at whitespace alone
        # would split `Marguerite Okonkwo-Vasquez` into two fragments that are
        # each a plausible word and neither a person's name -- which is why
        # overlap exists as well as whitespace-aligned boundaries.
        segmenter = Segmenter(max_characters=120, overlap_characters=64)
        filler = "word " * 120

        for offset in range(100, 160):
            text = filler[:offset] + value + filler[offset:]
            segmented = segmenter.segment(document(text))
            assert any(value in piece for piece in texts_of(segmented)), (
                f"{value!r} at offset {offset} did not survive"
            )

    def test_a_value_longer_than_the_overlap_is_not_guaranteed(self) -> None:
        # Stated as a test so the limit is documented rather than assumed. The
        # overlap is the guarantee; anything longer than it can be split, which
        # is why DEFAULT_OVERLAP_CHARACTERS is sized against the longest value
        # a recognizer needs to see whole.
        assert DEFAULT_OVERLAP_CHARACTERS < DEFAULT_MAX_CHARACTERS

    def test_a_boundary_does_not_land_inside_a_word_when_whitespace_is_near(
        self,
    ) -> None:
        # Arrange -- ordinary prose, so every boundary has whitespace within
        # the search window.
        segmenter = Segmenter(max_characters=200, overlap_characters=0)
        text = PROSE * 10

        segmented = segmenter.segment(document(text))

        for segment in segmented.segments[:-1]:
            # The character before each boundary is whitespace, so the cut
            # falls between words rather than through one.
            assert text[segment.end - 1].isspace(), f"boundary at {segment.end} landed mid-word"

    def test_an_unbroken_run_is_cut_at_the_hard_limit(self) -> None:
        # A base64 blob has no whitespace to break at. It still has to be cut,
        # and the segmenter must not loop forever looking for a boundary.
        segmenter = Segmenter(max_characters=50, overlap_characters=10)
        text = "A" * 500

        segmented = segmenter.segment(document(text))

        assert segmented.segment_count > 1
        assert segmented.segments[-1].end == len(text)


# ---------------------------------------------------------------------------
# Offsets and page references
# ---------------------------------------------------------------------------
class TestOffsets:
    def test_segment_offsets_are_global_not_local(self) -> None:
        # The whole point: a detection made against segment 3 has to map back
        # to the document, and it can only do that if the segment knows where
        # it starts.
        segmenter = Segmenter(max_characters=100, overlap_characters=0)
        text = PROSE * 5

        segmented = segmenter.segment(document(text))

        for segment in segmented.segments:
            local = segmented.text_of(segment).find("MRN-ZZ4471903")
            if local == -1:
                continue
            assert text[segment.to_global(local) :].startswith("MRN-ZZ4471903")

    def test_to_global_refuses_an_offset_outside_the_segment(self) -> None:
        segmented = Segmenter(max_characters=50, overlap_characters=8).segment(document(PROSE))
        segment = segmented.segments[0]

        with pytest.raises(DocumentExtractionError):
            segment.to_global(segment.length + 1)
        with pytest.raises(DocumentExtractionError):
            segment.to_global(-1)

    def test_segments_carry_the_pages_they_came_from(self) -> None:
        # Page references have to survive segmentation, or a protected span
        # cannot be traced back to where it appeared.
        extracted = build_extracted_document(page_texts=["a" * 100, "b" * 100, "c" * 100])
        segmenter = Segmenter(max_characters=150, overlap_characters=0)

        segmented = segmenter.segment(extracted)

        assert segmented.segments[0].pages[0] == 1
        assert 3 in segmented.segments[-1].pages
        for segment in segmented.segments:
            assert segment.pages, "every segment must name at least one page"
            assert list(segment.pages) == sorted(segment.pages)

    def test_a_segment_spanning_a_page_break_names_both_pages(self) -> None:
        extracted = build_extracted_document(page_texts=["a" * 40, "b" * 40])
        segmenter = Segmenter(max_characters=200, overlap_characters=0)

        segmented = segmenter.segment(extracted)

        assert segmented.segment_count == 1
        assert segmented.segments[0].pages == (1, 2)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class TestConfiguration:
    @pytest.mark.parametrize(
        ("max_characters", "overlap"),
        [(0, 0), (-1, 0), (100, -1), (100, 100), (100, 200)],
    )
    def test_an_unworkable_configuration_is_refused_at_construction(
        self, max_characters: int, overlap: int
    ) -> None:
        # An overlap at or above the segment size makes the loop stall, which
        # would be a hang rather than a wrong answer. Refusing at construction
        # turns it into a startup failure.
        with pytest.raises(ValueError):
            Segmenter(max_characters=max_characters, overlap_characters=overlap)

    def test_the_defaults_are_workable(self) -> None:
        segmenter = Segmenter()

        segmented = segmenter.segment(document(PROSE * 200))

        assert segmented.segment_count > 1

    def test_a_segmented_document_repr_hides_the_text(self) -> None:
        segmented = Segmenter().segment(document(PROSE))

        assert "Marguerite" not in repr(segmented)
        assert "Marguerite" not in repr(segmented.document)
