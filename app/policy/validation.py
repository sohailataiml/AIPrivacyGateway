"""Policy document validation and the operator-facing validation command.

Everything that turns raw JSON into a :class:`~app.policy.models.PolicyDocument`
goes through :func:`validate_policy_document`. That single door is what makes
"invalid policies cannot become active" a property of the system rather than a
convention: the service layer, the seed script, and the CLI all use it.

Failures are reported as field paths and pydantic error types only. The
document is configuration, but a rejected one may still be a draft an operator
pasted from somewhere sensitive, so no input value ever reaches a log line.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from app.domain.errors import InvalidRequestError
from app.policy.models import PolicyDocument

_logger = logging.getLogger(__name__)

INVALID_POLICY_MESSAGE: Final[str] = "The policy document is not valid."
UNREADABLE_POLICY_MESSAGE: Final[str] = "The policy document could not be read as JSON."

MAX_REPORTED_PROBLEMS: Final[int] = 20
"""Cap on the field paths carried in ``log_context``. Enough to fix, not a dump."""


def validate_policy_document(raw: Mapping[str, Any]) -> PolicyDocument:
    """Validate a raw policy mapping.

    Args:
        raw: The decoded JSON document. Never mutated.

    Returns:
        The validated, frozen document.

    Raises:
        InvalidRequestError: if the document violates the policy schema. Its
            ``log_context["problems"]`` holds ``field.path:error_type`` entries
            and no input values.
    """
    try:
        return PolicyDocument.model_validate(raw)
    except ValidationError as exc:
        raise InvalidRequestError(
            INVALID_POLICY_MESSAGE,
            log_context={"problems": _problem_paths(exc)},
        ) from exc


def validate_policy_file(path: Path) -> PolicyDocument:
    """Read and validate a policy document from disk.

    Raises:
        InvalidRequestError: if the file is not JSON or is not a valid policy.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidRequestError(
            UNREADABLE_POLICY_MESSAGE,
            log_context={"path": str(path), "reason": "unreadable"},
        ) from exc

    try:
        decoded = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise InvalidRequestError(
            UNREADABLE_POLICY_MESSAGE,
            log_context={"path": str(path), "reason": "malformed_json", "line": exc.lineno},
        ) from exc

    if not isinstance(decoded, Mapping):
        raise InvalidRequestError(
            INVALID_POLICY_MESSAGE,
            log_context={"path": str(path), "problems": ("root:not_an_object",)},
        )

    return validate_policy_document(decoded)


def _problem_paths(exc: ValidationError) -> tuple[str, ...]:
    """Render validation failures as field paths and error types.

    Only ``loc`` and ``type`` are read. Pydantic's ``msg`` and ``input`` echo
    the offending value and must never reach a log.
    """
    problems = (
        f"{'.'.join(str(part) for part in error['loc']) or 'root'}:{error['type']}"
        for error in exc.errors()
    )
    return tuple(sorted(set(problems)))[:MAX_REPORTED_PROBLEMS]


def main(argv: Sequence[str] | None = None) -> int:
    """Validate one or more policy files. Returns a process exit code."""
    parser = argparse.ArgumentParser(
        prog="policy-validate",
        description="Validate Secure AI Gateway policy documents.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="policy JSON files to validate")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    failures = 0
    for path in args.paths:
        try:
            document = validate_policy_file(path)
        except InvalidRequestError as exc:
            failures += 1
            _logger.error("%s: invalid -- %s %s", path, exc.public_message, exc.log_context)
        else:
            _logger.info(
                "%s: valid (name=%s, entities=%d, providers=%d)",
                path,
                document.name,
                len(document.entities),
                len(document.providers),
            )

    return 1 if failures else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
