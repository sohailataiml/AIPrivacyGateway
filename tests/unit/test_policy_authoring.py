"""The detector catalog and the authoring-time checks.

The catalog tests are mostly about *derivation*: the point of the module is
that it restates nothing, so the assertions compare it against the detector's
own tables rather than against literals. A test that hardcoded the entity list
would pass while the catalog drifted, which is the failure it exists to catch.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.detection.entities import DEFAULT_ENTITY_THRESHOLDS, SUPPORTED_ENTITY_TYPES
from app.domain.models import EntityAction
from app.policy.authoring import diff_documents, validate_draft
from app.policy.catalog import (
    RECOGNIZER_BUILTIN,
    RECOGNIZER_CUSTOM,
    detector_catalog,
)
from app.policy.defaults import DEFAULT_POLICY
from app.policy.models import PolicyDocument


def document(**overrides: Any) -> dict[str, Any]:
    base = DEFAULT_POLICY.model_dump(mode="json")
    base.update(overrides)
    return base


class TestDetectorCatalog:
    def test_it_covers_exactly_what_the_detector_can_emit(self) -> None:
        # Derived, not restated. A hardcoded list would drift silently.
        catalog = detector_catalog()

        assert {entry.entity_type for entry in catalog} == set(SUPPORTED_ENTITY_TYPES)

    def test_thresholds_come_from_the_detector_defaults(self) -> None:
        by_type = {entry.entity_type: entry for entry in detector_catalog()}

        for entity_type, threshold in DEFAULT_ENTITY_THRESHOLDS.items():
            assert by_type[entity_type].default_threshold == threshold

    def test_phone_number_default_is_the_real_one(self) -> None:
        # 0.40, not the 0.65 that discarded phone numbers. Pinned because this
        # is the value most likely to be "corrected" by someone reading the
        # original spec rather than the code.
        by_type = {entry.entity_type: entry for entry in detector_catalog()}

        assert by_type["PHONE_NUMBER"].default_threshold == 0.4

    def test_every_action_is_offered_for_every_type(self) -> None:
        # No per-type restriction exists in the engine, so inventing one here
        # would advertise a rule the pipeline does not enforce.
        expected = {action.value for action in EntityAction}

        for entry in detector_catalog():
            assert set(entry.supported_actions) == expected

    def test_custom_and_builtin_recognizers_are_distinguished(self) -> None:
        by_type = {entry.entity_type: entry for entry in detector_catalog()}

        assert by_type["MEDICAL_RECORD_NUMBER"].recognizer_type == RECOGNIZER_CUSTOM
        assert by_type["PERSON"].recognizer_type == RECOGNIZER_BUILTIN

    def test_high_severity_types_sort_first(self) -> None:
        catalog = detector_catalog()

        severities = [entry.severity for entry in catalog]
        assert severities == sorted(severities, reverse=True)

    def test_the_catalog_discloses_no_patterns(self) -> None:
        # A regex that finds API keys is a map of what a credential looks like.
        for entry in detector_catalog():
            rendered = repr(entry)
            assert "\\d" not in rendered
            assert "regex" not in rendered.lower() or entry.recognizer_type == RECOGNIZER_CUSTOM


class TestDraftValidation:
    def test_the_shipped_default_policy_is_publishable(self) -> None:
        # Non-vacuity for every rejection below.
        result = validate_draft(document())

        assert result.valid is True
        assert result.problems == ()

    @pytest.mark.parametrize("bad", [-0.1, 1.5])
    def test_a_threshold_outside_zero_to_one_is_refused(self, bad: float) -> None:
        raw = document()
        raw["entities"]["PERSON"]["min_score"] = bad

        result = validate_draft(raw)

        assert result.valid is False
        assert any("PERSON" in problem.field for problem in result.problems)

    def test_an_invalid_action_is_refused(self) -> None:
        raw = document()
        raw["entities"]["PERSON"]["action"] = "encrypt"

        assert validate_draft(raw).valid is False

    def test_an_entity_the_detector_cannot_emit_is_refused(self) -> None:
        raw = document()
        raw["entities"]["FAVOURITE_COLOUR"] = {"action": "tokenize", "min_score": 0.5}

        result = validate_draft(raw)

        assert result.valid is False
        assert any(problem.code == "unsupported_entity" for problem in result.problems)

    def test_an_unknown_recognizer_is_refused(self) -> None:
        raw = document()
        raw["entities"]["PERSON"]["recognizer"] = "handwriting-analysis"

        result = validate_draft(raw)

        assert result.valid is False
        assert any(problem.code == "unsupported_recognizer" for problem in result.problems)

    @pytest.mark.parametrize("ttl", [0, -1, 86_401])
    def test_an_invalid_session_ttl_is_refused(self, ttl: int) -> None:
        assert validate_draft(document(session_ttl_seconds=ttl)).valid is False

    @pytest.mark.parametrize("count", [0, -5, 10_001])
    def test_an_invalid_max_entity_count_is_refused(self, count: int) -> None:
        assert validate_draft(document(max_entities=count)).valid is False

    def test_an_empty_provider_allowlist_is_refused(self) -> None:
        assert validate_draft(document(providers={})).valid is False

    def test_a_provider_with_no_models_is_refused(self) -> None:
        assert validate_draft(document(providers={"mock": {"models": []}})).valid is False

    def test_problems_never_echo_a_value_from_the_document(self) -> None:
        # An operator may paste a real identifier into a description.
        raw = document()
        raw["entities"]["PERSON"]["description"] = "e.g. jane.doe@acme.internal"
        raw["entities"]["PERSON"]["min_score"] = 5.0

        result = validate_draft(raw)

        rendered = repr(result)
        assert "jane.doe@acme.internal" not in rendered
        assert "5.0" not in rendered


class TestRiskWarnings:
    def test_allowing_a_high_risk_entity_warns_without_blocking(self) -> None:
        # Legitimate but worth stopping to think about, so it is a warning and
        # the draft stays publishable.
        raw = document()
        raw["entities"]["US_SSN"]["action"] = "allow"

        result = validate_draft(raw)

        assert result.valid is True
        assert any(problem.code == "high_risk_allowed" for problem in result.warnings)

    def test_disabling_a_high_risk_entity_warns(self) -> None:
        raw = document()
        raw["entities"]["CREDIT_CARD"]["enabled"] = False

        result = validate_draft(raw)

        assert result.valid is True
        assert any(problem.code == "high_risk_disabled" for problem in result.warnings)

    def test_an_ordinary_change_produces_no_warning(self) -> None:
        raw = document()
        raw["entities"]["LOCATION"]["action"] = "allow"

        assert validate_draft(raw).warnings == ()


class TestDiff:
    def test_a_threshold_change_is_reported_with_both_values(self) -> None:
        before = PolicyDocument.model_validate(document())
        raw = document()
        raw["entities"]["PHONE_NUMBER"]["min_score"] = 0.65
        after = PolicyDocument.model_validate(raw)

        diff = diff_documents(before, after, from_version=3, to_version=4)

        change = next(c for c in diff.entity_changes if c.path == "PHONE_NUMBER.min_score")
        assert (change.before, change.after) == ("0.4", "0.65")

    def test_an_action_change_is_reported(self) -> None:
        before = PolicyDocument.model_validate(document())
        raw = document()
        raw["entities"]["US_SSN"]["action"] = "tokenize"
        after = PolicyDocument.model_validate(raw)

        diff = diff_documents(before, after, from_version=1, to_version=2)

        change = next(c for c in diff.entity_changes if c.path == "US_SSN.action")
        assert (change.before, change.after) == ("block", "tokenize")

    def test_added_and_removed_entities_are_distinguished(self) -> None:
        before = PolicyDocument.model_validate(document())
        raw = document()
        raw["entities"].pop("LOCATION")
        raw["entities"]["IP_ADDRESS"] = {"action": "redact", "min_score": 0.5}
        after = PolicyDocument.model_validate(raw)

        diff = diff_documents(before, after, from_version=1, to_version=2)

        kinds = {c.path: c.kind for c in diff.entity_changes}
        assert kinds["LOCATION"] == "removed"
        assert kinds["IP_ADDRESS"] == "added"

    def test_settings_changes_are_reported_separately_from_entities(self) -> None:
        before = PolicyDocument.model_validate(document())
        after = PolicyDocument.model_validate(document(session_ttl_seconds=600, max_entities=42))

        diff = diff_documents(before, after, from_version=1, to_version=2)

        paths = {c.path for c in diff.setting_changes}
        assert paths == {"session_ttl_seconds", "max_entities"}
        assert diff.entity_changes == ()

    def test_a_provider_allowlist_change_is_reported(self) -> None:
        before = PolicyDocument.model_validate(document())
        after = PolicyDocument.model_validate(
            document(providers={"mock": {"models": ["general-chat"]}})
        )

        diff = diff_documents(before, after, from_version=1, to_version=2)

        assert any(c.path == "providers" for c in diff.setting_changes)

    def test_identical_versions_produce_no_changes(self) -> None:
        # Non-vacuity: the diff must not report churn for an unchanged republish.
        before = PolicyDocument.model_validate(document())
        after = PolicyDocument.model_validate(document())

        diff = diff_documents(before, after, from_version=1, to_version=2)

        assert diff.total == 0
