"""A masked rendering of what the provider was actually sent.

architecture.md 22.6 forbids the provider request body in the Privacy Inspector,
and allows a "Protected Prompt Preview" only if it is off in production by
default. This is that preview, narrowed: the masking happens here, on the
server, so the browser is never sent a full token and cannot be trusted to hide
one. A frontend that received ``⟦SGW:PERSON:01J8Z6...⟧`` and rendered dots over
it would still have the token in memory, in the network tab, and in any error
report the page produced.

What a mask discloses, stated plainly so the trade is visible:

* **The token identifier: never.** It is replaced before the value leaves this
  module, so the vault key it names cannot be reached from a browser.
* **The entity type: yes**, and it is already in ``PrivacySummary.entity_types``
  and in every ``/v1/detect`` response. Nothing new.
* **The surrounding text: yes.** For a chat prompt this is what the caller
  typed and already holds, so the preview echoes their own input back at them.
  For a document it is extracted body text, which is a genuinely larger step --
  see ``preview_of``.
* **The original sensitive values: never.** They are gone by the time the
  pipeline reaches this point; the protected text holds tokens in their place,
  and this module only ever shortens those.

Off unless ``PROTECTED_PREVIEW_ENABLED`` is set, so a deployment opts in rather
than discovers it.
"""

from __future__ import annotations

import re
from typing import Final

from app.domain.models import ProtectedEntitySummary
from app.tokenization.grammar import (
    LEFT_DELIMITER,
    NAMESPACE,
    REDACTED_MARKER,
    RIGHT_DELIMITER,
    TOKEN_PATTERN,
)

MASK: Final = "••••"
"""What replaces a token identifier. Four dots, a fixed width.

Fixed rather than proportional to the identifier: a mask whose length tracked
the thing it hides would leak that length, and although a gateway token id is
always 26 characters, a preview that habitually encoded lengths is a habit worth
not forming.
"""

MAX_PREVIEW_CHARS: Final = 600
"""Ceiling on the preview. Enough to show the shape of a protected prompt.

A bound rather than the whole text, because this field travels in every chat
response and a 32k-character prompt would make the inspector the largest thing
on the wire for no additional insight -- the first few sentences show what
happened as well as all of them.
"""

TRUNCATION_SUFFIX: Final = " …"

_REDACTION_PATTERN: Final = re.compile(
    f"{re.escape(LEFT_DELIMITER)}{NAMESPACE}:{REDACTED_MARKER}:"
    f"(?P<entity_type>[A-Z0-9_]{{1,64}}){re.escape(RIGHT_DELIMITER)}"
)
"""Redaction placeholders. Not matched by ``TOKEN_PATTERN``, which requires an
identifier -- ``REDACTED`` is a reserved marker and never an entity type."""


def _mask_token(match: re.Match[str]) -> str:
    return f"{LEFT_DELIMITER}{match.group('entity_type')}:{MASK}{RIGHT_DELIMITER}"


def mask_tokens(text: str) -> str:
    """Replace every gateway token and redaction placeholder with a masked form.

    ``⟦SGW:PERSON:01J8Z6J4M7Y9Q2K3T4V5W6X7Y8⟧`` becomes ``⟦PERSON:••••⟧``.

    The namespace goes too. It identifies the gateway rather than the value, but
    keeping it would make a masked preview look enough like a real token that
    someone might try to resolve one, and the shorter form reads better in a
    panel that is trying to make a point about what was protected.
    """
    masked = TOKEN_PATTERN.sub(_mask_token, text)
    return _REDACTION_PATTERN.sub(
        lambda match: f"{LEFT_DELIMITER}{match.group('entity_type')}:REDACTED{RIGHT_DELIMITER}",
        masked,
    )


def truncate(text: str, *, limit: int = MAX_PREVIEW_CHARS) -> str:
    """Shorten to ``limit`` characters without splitting a mask in half.

    A cut landing inside ``⟦PERSON:••••⟧`` would leave a dangling delimiter that
    reads as a malformed token rather than as a truncation.
    """
    if len(text) <= limit:
        return text
    cut = text[:limit]
    opened = cut.rfind(LEFT_DELIMITER)
    closed = cut.rfind(RIGHT_DELIMITER)
    if opened > closed:
        cut = cut[:opened]
    return cut.rstrip() + TRUNCATION_SUFFIX


def preview_of(messages: tuple[str, ...]) -> str:
    """Build the masked preview from the protected messages, newest last.

    Joined with blank lines rather than reconstructing the provider's exact
    serialization: the point is to show an operator that values were replaced,
    not to reproduce a payload byte for byte. The canonical outbound bytes are
    attested by a keyed digest (ADR-0024) and are never returned.
    """
    return truncate(mask_tokens("\n\n".join(messages).strip()))


OUTBOUND_SCAN_PASSED: Final = "passed"
"""The only verdict a completed request can carry.

The outbound scan is fail-closed: a request that did not pass never reaches a
provider, so no response exists to report a failure on. Reporting it anyway is
worth doing -- an operator reading the panel should see the check named, not
infer it from the absence of a refusal.
"""


def applied_actions(messages: tuple[str, ...]) -> tuple[ProtectedEntitySummary, ...]:
    """Count what was actually applied, per entity type, by reading the tokens.

    Derived from the protected text rather than from the policy. A value scoring
    below its type's threshold is left in place whatever the policy says about
    that type, so reading the policy would report protection that did not
    happen -- the tokens are the record of what was really done.

    ``pseudonymize`` is indistinguishable from ``tokenize`` here: both mint a
    resolvable token with the same grammar. It is reported as ``tokenize``,
    which is what the token in the text actually is, rather than guessed at from
    the policy.
    """
    counts: dict[tuple[str, str], int] = {}
    for message in messages:
        for match in TOKEN_PATTERN.finditer(message):
            key = (match.group("entity_type"), "tokenize")
            counts[key] = counts.get(key, 0) + 1
        for match in _REDACTION_PATTERN.finditer(message):
            key = (match.group("entity_type"), "redact")
            counts[key] = counts.get(key, 0) + 1

    return tuple(
        ProtectedEntitySummary(entity_type=entity_type, count=count, action=action)
        for (entity_type, action), count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0][0])
        )
    )
