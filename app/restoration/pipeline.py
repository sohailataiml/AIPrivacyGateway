"""Output parsing and restoration -- the last stage before the caller.

The provider has replied with text that still contains gateway tokens. This
stage turns those tokens back into original values, and nothing else.

Four properties are load-bearing:

1. **Parse, never replace globally.** Candidates come from
   ``app.tokenization.grammar.find_tokens``, which validates every field of
   every hit. A partial, nested, or mistyped token is left exactly as the
   provider wrote it, because a string that is not a token cannot address a
   vault record.
2. **One pass, no rescanning.** Substitution walks the *original* text once and
   emits segments. A restored original value is appended to the output and never
   looked at again, so a stored value that happens to look like a token -- which
   an attacker could arrange by submitting token-shaped text as input -- cannot
   trigger a second resolution. Restoration is not recursive and has no fixpoint
   loop to exploit.
3. **Fail closed after the provider call.** If the vault is unreachable, the
   error propagates and the caller gets nothing. Half-restored text is never
   returned: it would be indistinguishable from a successful response with
   fewer entities.
4. **Counts leave, values do not.** The summary carries integers. No log line,
   metric, or error context in this module contains restored text, an original
   value, or a full token.

Error contract:

* an unusable provider payload -- non-string content, blank model, or a body
  over ``max_output_chars`` -- raises ``ProviderResponseInvalidError``;
* an unresolvable token under ``UnknownTokenAction.FAIL`` raises
  ``RestorationError``;
* a vault outage raises ``VaultUnavailableError``, and a vault record that
  fails authentication raises ``VaultEncryptionError``. Neither is caught here.

Newly generated PII (architecture 9.8) is out of scope for restoration. A model
may invent an email address that was never in the input; it is not a token, it
has no mapping, and this stage passes it through untouched rather than
inventing a substitution. Detecting such text is the job of a separate optional
output scan, and version 1 does not claim to prevent it.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final

from app.domain.errors import ProviderResponseInvalidError, RestorationError
from app.domain.models import PrivacySummary, ProviderResponse, UnknownTokenAction
from app.restoration.results import RestoredOutput
from app.tokenization.grammar import TokenMatch, find_tokens, format_redaction

if TYPE_CHECKING:
    from uuid import UUID

    from app.restoration.protocols import PolicyLike, VaultLike

logger = logging.getLogger("app.restoration")

DEFAULT_MAX_OUTPUT_CHARS: Final[int] = 131_072
"""Ceiling on provider output, checked before any parsing or vault work.

Sized well above any legitimate completion. Its purpose is to bound the work an
upstream provider -- compromised, misconfigured, or merely looping -- can force
this stage to perform.
"""


class OutputPipeline:
    """Restores gateway tokens in one provider response.

    Stateless and safe to share across requests: every call carries its own
    tenant, session, and policy, and nothing is cached between calls.
    """

    __slots__ = ("_max_output_chars", "_vault")

    def __init__(
        self,
        *,
        vault: VaultLike,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    ) -> None:
        if max_output_chars < 1:
            raise ValueError("max_output_chars must be at least 1")
        self._vault = vault
        self._max_output_chars = max_output_chars

    async def restore(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        response: ProviderResponse,
        policy: PolicyLike,
    ) -> RestoredOutput:
        """Return ``response`` with this session's tokens replaced by originals.

        The result is authorized output. Hand it only to the principal that made
        the request.

        Raises:
            ProviderResponseInvalidError: the payload is malformed or oversized.
            RestorationError: an unknown token was found and policy says fail.
            VaultUnavailableError: the vault could not be reached.
            VaultEncryptionError: a stored record failed authentication.
        """
        text = _validated_content(response, limit=self._max_output_chars)
        matches = find_tokens(text)
        if not matches:
            return _passthrough(response, text)

        candidates = {match.text for match in matches}
        resolved = await self._vault.resolve_many(
            tenant_id=tenant_id,
            session_id=session_id,
            tokens=candidates,
        )
        unknown = candidates - resolved.keys()
        action = policy.unknown_output_token_action
        if unknown and action is UnknownTokenAction.FAIL:
            # Count only. The tokens themselves stay out of the error context.
            logger.warning(
                "restoration failed on unresolvable tokens",
                extra={"unknown_tokens": len(unknown)},
            )
            raise RestorationError(log_context={"unknown_tokens": len(unknown)})
        if unknown:
            logger.info(
                "response contained unresolvable tokens",
                extra={"unknown_tokens": len(unknown), "unknown_token_action": str(action)},
            )

        restored_text = _substitute(text=text, matches=matches, resolved=resolved, action=action)
        summary = PrivacySummary(restored=len(resolved), unknown_tokens=len(unknown))
        return RestoredOutput(
            text=restored_text,
            summary=summary,
            model=response.model,
            usage=response.usage,
        )


def _substitute(
    *,
    text: str,
    matches: tuple[TokenMatch, ...],
    resolved: dict[str, str],
    action: UnknownTokenAction,
) -> str:
    """Rebuild ``text`` from segments, replacing each match at most once.

    Offsets stay valid because the source string is never mutated: the walk
    reads ``text`` and appends to a separate list. Substituted values are
    appended verbatim and are never re-examined, which is what makes recursive
    restoration structurally impossible rather than merely unlikely.
    """
    pieces: list[str] = []
    cursor = 0
    for match in matches:
        pieces.append(text[cursor : match.start])
        pieces.append(_replacement(match=match, resolved=resolved, action=action))
        cursor = match.end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _replacement(
    *,
    match: TokenMatch,
    resolved: dict[str, str],
    action: UnknownTokenAction,
) -> str:
    """Return the text that stands in for one matched token.

    A known token becomes its original value. An unknown one follows policy:
    ``PRESERVE`` keeps the token text, which discloses nothing beyond what the
    provider already emitted, and ``REDACT`` swaps in the reserved placeholder,
    which by construction can never parse back into a resolvable token.
    ``FAIL`` has already raised by the time this runs.
    """
    original = resolved.get(match.text)
    if original is not None:
        return original
    if action is UnknownTokenAction.REDACT:
        return format_redaction(match.token.entity_type)
    return match.text


def _validated_content(response: ProviderResponse, *, limit: int) -> str:
    """Return the response body, or reject the payload.

    Size is checked before parsing so that an oversized body costs one length
    comparison rather than a full scan and a vault round trip.
    """
    # Typed as ``object`` on purpose. ``ProviderResponse`` is a plain dataclass,
    # so a third-party adapter can put anything in these fields; the annotation
    # is a promise, not a runtime guarantee, and this stage is downstream of the
    # network. The check costs nothing and turns a would-be ``AttributeError``
    # deep in the scanner into a clean 502.
    content: object = response.content
    model: object = response.model
    if not isinstance(content, str):
        raise ProviderResponseInvalidError(log_context={"reason": "content_not_text"})
    if not isinstance(model, str) or not model.strip():
        raise ProviderResponseInvalidError(log_context={"reason": "missing_model"})
    if len(content) > limit:
        # Lengths are not sensitive; the body is, and is never logged.
        raise ProviderResponseInvalidError(
            log_context={"reason": "output_too_large", "characters": len(content), "limit": limit},
        )
    return content


def _passthrough(response: ProviderResponse, text: str) -> RestoredOutput:
    """Wrap a response that contains no tokens. No vault call is made."""
    return RestoredOutput(
        text=text,
        summary=PrivacySummary(),
        model=response.model,
        usage=response.usage,
    )
