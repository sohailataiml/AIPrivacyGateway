"""The masked preview, and everything it must never contain.

This is a privacy suite rather than a unit suite because the property under test
is a disclosure boundary: the preview is the one field that renders the provider
request body, and architecture.md 22.6 otherwise forbids that entirely. What
makes it acceptable is that the masking happens on the server and is one-way, so
these tests are the enforcement.

The canary values are synthetic and deliberately distinctive, so a test that
failed the wrong way would make the leak obvious rather than plausible.
"""

from __future__ import annotations

import pytest

from app.pipeline.preview import (
    MASK,
    MAX_PREVIEW_CHARS,
    TRUNCATION_SUFFIX,
    applied_actions,
    mask_tokens,
    preview_of,
    truncate,
)
from app.tokenization.grammar import format_token

pytestmark = pytest.mark.privacy

TOKEN_ID = "01J8Z6J4M7Y9Q2K3T4V5W6X7Y8"
OTHER_ID = "01J8Z6J4M7Y9Q2K3T4V5W6X7Y9"

PERSON_TOKEN = format_token("PERSON", TOKEN_ID)
EMAIL_TOKEN = format_token("EMAIL_ADDRESS", OTHER_ID)
REDACTION = "⟦SGW:REDACTED:US_SSN⟧"

PROTECTED = (
    f"Patient {PERSON_TOKEN} was contacted at {EMAIL_TOKEN} and their number is {REDACTION}."
)


class TestMasking:
    def test_a_token_identifier_never_survives_masking(self) -> None:
        # The identifier names a vault key. It is the one thing a browser must
        # never receive, whatever else the preview shows.
        masked = mask_tokens(PROTECTED)

        assert TOKEN_ID not in masked
        assert OTHER_ID not in masked

    def test_the_whole_token_never_survives(self) -> None:
        masked = mask_tokens(PROTECTED)

        assert PERSON_TOKEN not in masked
        assert EMAIL_TOKEN not in masked

    def test_the_namespace_is_dropped_so_a_mask_cannot_be_mistaken_for_a_token(
        self,
    ) -> None:
        masked = mask_tokens(PROTECTED)

        assert "SGW:" not in masked

    def test_the_entity_type_is_kept_because_it_is_already_public(self) -> None:
        # Already in PrivacySummary.entity_types and in every /v1/detect
        # response, so keeping it discloses nothing new -- and it is the whole
        # point of the panel.
        masked = mask_tokens(PROTECTED)

        assert "PERSON" in masked
        assert "EMAIL_ADDRESS" in masked

    def test_the_mask_is_a_fixed_width(self) -> None:
        # A mask sized to what it hides would leak that size.
        masked = mask_tokens(f"{format_token('PERSON', TOKEN_ID)}")

        assert masked == f"⟦PERSON:{MASK}⟧"

    def test_surrounding_text_is_preserved(self) -> None:
        # Non-vacuity: a function that returned a constant would pass every
        # assertion above.
        masked = mask_tokens(PROTECTED)

        assert "Patient" in masked
        assert "was contacted at" in masked

    def test_a_redaction_placeholder_is_reported_as_redacted(self) -> None:
        masked = mask_tokens(REDACTION)

        assert masked == "⟦US_SSN:REDACTED⟧"
        assert "SGW" not in masked

    def test_text_with_no_tokens_is_unchanged(self) -> None:
        assert mask_tokens("Nothing sensitive here.") == "Nothing sensitive here."


class TestTruncation:
    def test_short_text_is_returned_whole(self) -> None:
        assert truncate("short") == "short"

    def test_long_text_is_cut_and_marked(self) -> None:
        result = truncate("x" * (MAX_PREVIEW_CHARS + 500))

        assert result.endswith(TRUNCATION_SUFFIX)
        assert len(result) <= MAX_PREVIEW_CHARS + len(TRUNCATION_SUFFIX)

    def test_a_cut_never_splits_a_mask_in_half(self) -> None:
        # A dangling delimiter reads as a malformed token rather than as a
        # truncation, and a half-mask is exactly what a naive slice produces.
        text = "y" * (MAX_PREVIEW_CHARS - 4) + f"⟦PERSON:{MASK}⟧ tail"

        result = truncate(text)

        assert "⟦PERSON" not in result or "⟧" in result

    def test_truncation_cannot_expose_a_partial_identifier(self) -> None:
        # The masking runs first, so there is no identifier left to split. This
        # pins the ordering rather than trusting it.
        text = f"{'z' * (MAX_PREVIEW_CHARS - 6)}{PERSON_TOKEN} tail"

        result = truncate(mask_tokens(text))

        assert TOKEN_ID not in result
        assert TOKEN_ID[:8] not in result


class TestAppliedActions:
    def test_it_counts_tokens_by_type(self) -> None:
        summary = applied_actions((PROTECTED,))
        by_type = {item.entity_type: item for item in summary}

        assert by_type["PERSON"].count == 1
        assert by_type["PERSON"].action == "tokenize"
        assert by_type["EMAIL_ADDRESS"].action == "tokenize"

    def test_it_reports_redactions_distinctly(self) -> None:
        summary = applied_actions((PROTECTED,))
        by_type = {item.entity_type: item for item in summary}

        assert by_type["US_SSN"].action == "redact"

    def test_it_counts_repeats_of_one_type(self) -> None:
        text = f"{format_token('PERSON', TOKEN_ID)} and {format_token('PERSON', OTHER_ID)}"

        [person] = applied_actions((text,))

        assert person.count == 2

    def test_it_reads_the_tokens_rather_than_the_policy(self) -> None:
        # A value scoring below its threshold is left in place whatever the
        # policy says about its type. Counting from the policy would report
        # protection that did not happen; there is no token here, so there is
        # nothing to report.
        assert applied_actions(("Call 415-555-0142.",)) == ()

    def test_it_carries_no_identifier(self) -> None:
        rendered = repr(applied_actions((PROTECTED,)))

        assert TOKEN_ID not in rendered
        assert OTHER_ID not in rendered


class TestPreviewOf:
    def test_it_masks_and_joins_every_message(self) -> None:
        preview = preview_of((f"First {PERSON_TOKEN}", f"Second {EMAIL_TOKEN}"))

        assert TOKEN_ID not in preview
        assert OTHER_ID not in preview
        assert "First" in preview
        assert "Second" in preview

    def test_it_bounds_its_own_length(self) -> None:
        preview = preview_of(("w" * 50_000,))

        assert len(preview) <= MAX_PREVIEW_CHARS + len(TRUNCATION_SUFFIX)

    def test_an_empty_conversation_produces_an_empty_preview(self) -> None:
        assert preview_of(()) == ""
