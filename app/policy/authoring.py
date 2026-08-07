"""Authoring-time checks and diffs for the policy management surface.

Separate from `app.policy.validation` on purpose. That module answers "is this a
structurally valid policy document" and is on the path every request-time
resolution takes. This one answers "is this a sensible thing for an operator to
publish", which is a larger and slower question -- it needs the detector catalog
-- and is only ever asked while editing.

Keeping them apart means the authoring rules cannot slow down or, worse, start
rejecting a policy that is already live. A document that passed at publish time
must keep resolving forever, even if a later build tightens what it will accept
from an editor.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from app.domain.errors import InvalidRequestError
from app.domain.models import EntityAction
from app.policy.catalog import known_entity_types, known_recognizers
from app.policy.models import PolicyDocument
from app.policy.validation import validate_policy_document

MAX_REPORTED_PROBLEMS: Final[int] = 20


@dataclass(frozen=True, slots=True)
class ValidationProblem:
    """One reason a draft cannot be published.

    ``field`` is a dotted path into the document and ``code`` is a stable
    machine-readable slug. Neither carries a value from the document: a draft is
    configuration, but an operator may have pasted a real identifier into a
    description field, and a validation error is not a place to echo it back.
    """

    field: str
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    valid: bool
    problems: tuple[ValidationProblem, ...]
    warnings: tuple[ValidationProblem, ...]
    """Non-blocking. A risky-but-legitimate change is warned about, not refused."""


# -- Validation ---------------------------------------------------------------
def validate_draft(raw: Mapping[str, Any]) -> ValidationResult:
    """Check a draft document for publishability.

    Structural validation runs first, through the same door request-time
    resolution uses. Only if the document parses do the authoring rules run,
    because they assume a well-formed shape.
    """
    problems: list[ValidationProblem] = []

    try:
        document = validate_policy_document(raw)
    except InvalidRequestError as exc:
        # The only failure `validate_policy_document` raises. Its log_context
        # carries `field.path:error_type` entries and never an input value,
        # which is precisely what is safe to hand back to a caller.
        paths = list(exc.log_context.get("problems") or ["document:invalid"])
        return ValidationResult(
            valid=False,
            problems=tuple(
                ValidationProblem(
                    field=str(path).split(":", 1)[0],
                    code=str(path).split(":", 1)[-1],
                    message="This field is not valid for a policy document.",
                )
                for path in paths[:MAX_REPORTED_PROBLEMS]
            ),
            warnings=(),
        )

    problems.extend(_unknown_entities(document))
    problems.extend(_unknown_recognizers(document))

    return ValidationResult(
        valid=not problems,
        problems=tuple(problems[:MAX_REPORTED_PROBLEMS]),
        warnings=tuple(_warnings(document)),
    )


def _unknown_entities(document: PolicyDocument) -> list[ValidationProblem]:
    known = known_entity_types()
    return [
        ValidationProblem(
            field=f"entities.{name}",
            code="unsupported_entity",
            message="The detector cannot emit this entity type.",
        )
        for name in sorted(document.entities)
        if name not in known
    ]


def _unknown_recognizers(document: PolicyDocument) -> list[ValidationProblem]:
    known = known_recognizers()
    return [
        ValidationProblem(
            field=f"entities.{name}.recognizer",
            code="unsupported_recognizer",
            message="No recognizer of this name is configured.",
        )
        for name, rule in sorted(document.entities.items())
        if rule.recognizer is not None and rule.recognizer not in known
    ]


HIGH_RISK_ENTITIES: Final[frozenset[str]] = frozenset(
    {"US_SSN", "CREDIT_CARD", "API_KEY", "ACCESS_TOKEN", "US_PASSPORT"}
)
"""Types whose exposure is not recoverable. Weakening a rule on one is warned about."""


def _warnings(document: PolicyDocument) -> list[ValidationProblem]:
    """Advisory notes. Never blocking.

    An operator may have a good reason to allow an entity type this build
    considers high risk, and refusing would make the product wrong for them.
    Saying so plainly before they publish is the useful behaviour.
    """
    notes: list[ValidationProblem] = []
    for name in sorted(document.entities):
        rule = document.entities[name]
        if name not in HIGH_RISK_ENTITIES:
            continue
        if not rule.enabled:
            notes.append(
                ValidationProblem(
                    field=f"entities.{name}.enabled",
                    code="high_risk_disabled",
                    message="This high-risk type falls back to the default action when disabled.",
                )
            )
        elif rule.action is EntityAction.ALLOW:
            notes.append(
                ValidationProblem(
                    field=f"entities.{name}.action",
                    code="high_risk_allowed",
                    message="This high-risk type would be sent to the provider unprotected.",
                )
            )
    return notes


# -- Diff ---------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class FieldChange:
    """One value that differs between two versions, rendered as text.

    ``before`` and ``after`` are strings because a diff is for reading. They are
    policy configuration -- thresholds, actions, aliases -- and never document
    content, so there is nothing sensitive to redact.
    """

    path: str
    before: str | None
    after: str | None
    kind: str
    """``added``, ``removed``, or ``changed``."""


@dataclass(frozen=True, slots=True)
class PolicyDiff:
    from_version: int
    to_version: int
    entity_changes: tuple[FieldChange, ...]
    setting_changes: tuple[FieldChange, ...]

    @property
    def total(self) -> int:
        return len(self.entity_changes) + len(self.setting_changes)


def _rule_fields(rule: Any) -> dict[str, str]:
    return {
        "action": str(rule.action.value),
        "min_score": f"{rule.min_score:g}",
        "enabled": str(rule.enabled).lower(),
        "priority": "—" if rule.priority is None else str(rule.priority),
        "recognizer": rule.recognizer or "—",
    }


def diff_documents(
    before: PolicyDocument, after: PolicyDocument, *, from_version: int, to_version: int
) -> PolicyDiff:
    """Compare two validated documents.

    Computed from two stored versions rather than reconstructed in a browser, so
    what the UI shows is what the database holds.
    """
    entity_changes: list[FieldChange] = []

    for name in sorted(set(before.entities) | set(after.entities)):
        old = before.entities.get(name)
        new = after.entities.get(name)
        if old is None and new is not None:
            entity_changes.append(
                FieldChange(
                    path=name,
                    before=None,
                    after=f"{new.action.value} @ {new.min_score:g}",
                    kind="added",
                )
            )
        elif old is not None and new is None:
            entity_changes.append(
                FieldChange(
                    path=name,
                    before=f"{old.action.value} @ {old.min_score:g}",
                    after=None,
                    kind="removed",
                )
            )
        elif old is not None and new is not None:
            old_fields, new_fields = _rule_fields(old), _rule_fields(new)
            entity_changes.extend(
                FieldChange(
                    path=f"{name}.{field}",
                    before=old_fields[field],
                    after=new_fields[field],
                    kind="changed",
                )
                for field in old_fields
                if old_fields[field] != new_fields[field]
            )

    setting_changes = [
        FieldChange(path=path, before=old, after=new, kind="changed")
        for path, old, new in (
            (
                "session_ttl_seconds",
                str(before.session_ttl_seconds),
                str(after.session_ttl_seconds),
            ),
            ("max_entities", str(before.max_entities), str(after.max_entities)),
            (
                "unknown_output_token_action",
                before.unknown_output_token_action.value,
                after.unknown_output_token_action.value,
            ),
            ("providers", _providers_text(before), _providers_text(after)),
        )
        if old != new
    ]

    return PolicyDiff(
        from_version=from_version,
        to_version=to_version,
        entity_changes=tuple(entity_changes),
        setting_changes=tuple(setting_changes),
    )


def _providers_text(document: PolicyDocument) -> str:
    return "; ".join(
        f"{alias}: {', '.join(sorted(rule.models))}"
        for alias, rule in sorted(document.providers.items())
    )
