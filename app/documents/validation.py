"""Boundary validation for uploads.

Everything here runs before a byte is sealed or stored, and every function is
pure. Three separate things are checked, because they fail in three different
ways:

* **The filename** is attacker-controlled text that will be stored and later
  handed back. It is normalized to a bare name; directory components, control
  characters, and reserved device names never survive.
* **The declared type** is a claim, not evidence. It must be on the allowlist,
  it must agree with the extension, and it must agree with the file's own magic
  bytes -- a ``.txt`` name on a PDF body is rejected rather than believed.
* **The length** is checked twice: the declared ``Content-Length`` up front, and
  the real byte count as it streams. A declared length is a hint, and treating
  it as a fact is how a size limit gets bypassed by omitting the header.

Nothing here logs. A filename is Restricted, so the cheapest way to guarantee it
is never logged is to have no logging statements at all.
"""

from __future__ import annotations

import unicodedata
from pathlib import PurePosixPath, PureWindowsPath
from typing import Final

from app.documents.models import (
    CONTENT_TYPE_TXT,
    EXTENSION_TO_CONTENT_TYPE,
    SUPPORTED_TYPES,
)
from app.domain.errors import (
    DocumentInvalidError,
    DocumentTooLargeError,
    DocumentTypeUnsupportedError,
)

MAX_FILENAME_CHARS: Final = 255
MAGIC_SNIFF_BYTES: Final = 8
"""Enough for every signature in ``SUPPORTED_TYPES``; the longest is 5 bytes."""

_RESERVED_WINDOWS_NAMES: Final = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{digit}" for digit in range(1, 10)),
        *(f"lpt{digit}" for digit in range(1, 10)),
    }
)

_BIDI_CONTROLS: Final = frozenset(
    "؜"  # arabic letter mark
    "‎‏"  # left-to-right and right-to-left marks
    "‪‫‬‭‮"  # embeddings, override, pop
    "⁦⁧⁨⁩"  # isolates and pop
)
"""Characters that reorder how a name renders without changing what it is.

``report\\u202etxt.pdf`` displays as ``report.fdp.txt``, so what a reviewer
approves and what is stored are two different names. These are rejected
individually rather than by refusing the whole ``Cf`` category, because ``Cf``
also contains the zero-width joiner and non-joiner, which are ordinary in
Persian, Indic scripts, and emoji sequences.
"""


def normalize_filename(raw: str) -> str:
    """Return a safe bare filename, or raise.

    Rejects rather than repairs wherever repairing would be a guess. A caller
    who sent ``../../etc/passwd`` gets an error, not a silently rewritten name:
    the rewrite would store something the caller never asked for under a name
    they would not recognise.

    Raises:
        DocumentInvalidError: empty, oversized, traversing, or containing
            control characters, bidirectional overrides, separators, or a
            reserved device name.
    """
    if not raw or not raw.strip():
        raise DocumentInvalidError(log_context={"reason": "filename_empty"})

    # NFC first: two different byte sequences that render identically should
    # not be two different stored names.
    candidate = unicodedata.normalize("NFC", raw).strip()

    if len(candidate) > MAX_FILENAME_CHARS:
        raise DocumentInvalidError(
            log_context={"reason": "filename_too_long", "length": len(candidate)}
        )
    if "\x00" in candidate:
        raise DocumentInvalidError(log_context={"reason": "filename_null_byte"})
    if any(unicodedata.category(character) == "Cc" for character in candidate):
        raise DocumentInvalidError(log_context={"reason": "filename_control_character"})
    if not _BIDI_CONTROLS.isdisjoint(candidate):
        raise DocumentInvalidError(log_context={"reason": "filename_bidi_control"})

    # Both flavours, because the gateway does not know what the storage or the
    # eventual reader treats as a separator.
    if "/" in candidate or "\\" in candidate:
        raise DocumentInvalidError(log_context={"reason": "filename_contains_separator"})
    if PurePosixPath(candidate).name != candidate or PureWindowsPath(candidate).name != candidate:
        raise DocumentInvalidError(log_context={"reason": "filename_not_a_bare_name"})
    if candidate in {".", ".."}:
        raise DocumentInvalidError(log_context={"reason": "filename_relative"})
    if candidate.split(".")[0].lower() in _RESERVED_WINDOWS_NAMES:
        raise DocumentInvalidError(log_context={"reason": "filename_reserved"})

    return candidate


def resolve_content_type(*, filename: str, declared: str | None) -> str:
    """Return the content type to store, agreeing with the extension.

    A declared type must be supported and must match the extension. When
    nothing is declared the extension decides, because an unsupported file with
    no declared type is still unsupported.

    Raises:
        DocumentTypeUnsupportedError: unknown extension, unknown declared type,
            or the two disagree.
    """
    extension = _extension_of(filename)
    from_extension = EXTENSION_TO_CONTENT_TYPE.get(extension)
    if from_extension is None:
        raise DocumentTypeUnsupportedError(
            log_context={"reason": "extension_not_supported", "extension": extension}
        )

    if declared is None:
        return from_extension

    normalized = declared.split(";")[0].strip().lower()
    if normalized not in SUPPORTED_TYPES:
        raise DocumentTypeUnsupportedError(
            log_context={"reason": "content_type_not_supported", "content_type": normalized}
        )
    if normalized != from_extension:
        # Believing the declared type here is how a PDF gets stored as text and
        # handed to a text extractor later.
        raise DocumentTypeUnsupportedError(
            log_context={
                "reason": "content_type_extension_mismatch",
                "content_type": normalized,
                "extension": extension,
            }
        )
    return normalized


def verify_magic(*, content_type: str, head: bytes) -> None:
    """Check the file's own first bytes against its declared type.

    Raises:
        DocumentTypeUnsupportedError: the body does not look like its type.
        DocumentInvalidError: a text document that is not valid UTF-8.
    """
    supported = SUPPORTED_TYPES.get(content_type)
    if supported is None:  # pragma: no cover - resolve_content_type ran first
        raise DocumentTypeUnsupportedError(
            log_context={"reason": "content_type_not_supported", "content_type": content_type}
        )

    if supported.magic:
        if not any(head.startswith(signature) for signature in supported.magic):
            raise DocumentTypeUnsupportedError(
                log_context={"reason": "magic_bytes_mismatch", "content_type": content_type}
            )
        return

    # A signature-less type still has to be checked *against* the others. A PDF
    # is valid ASCII for its first several bytes, so decodability alone would
    # wave `%PDF-1.7` through under a .txt name -- and the next phase's text
    # extractor would then be handed a binary container.
    for other in SUPPORTED_TYPES.values():
        if other.content_type == content_type:
            continue
        if any(head.startswith(signature) for signature in other.magic):
            raise DocumentTypeUnsupportedError(
                log_context={
                    "reason": "magic_bytes_match_another_type",
                    "content_type": content_type,
                    "actual_content_type": other.content_type,
                }
            )

    if content_type == CONTENT_TYPE_TXT:
        # No signature exists for plain text, so decodability is the evidence.
        # A truncated multi-byte character at the sniff boundary is not an
        # error, which is why this decodes with an incremental decoder rather
        # than calling bytes.decode on a prefix.
        import codecs

        decoder = codecs.getincrementaldecoder("utf-8")()
        try:
            decoder.decode(head)
        except UnicodeDecodeError:
            raise DocumentInvalidError(log_context={"reason": "text_not_utf8"}) from None


def enforce_declared_length(*, declared: int | None, limit: int) -> None:
    """Reject an upload whose declared length already exceeds the limit.

    A cheap early rejection only. The real enforcement is
    :func:`enforce_streamed_length`, because a declared length can be absent or
    simply untrue.

    Raises:
        DocumentTooLargeError: the declared length is over the limit.
        DocumentInvalidError: the declared length is negative.
    """
    if declared is None:
        return
    if declared < 0:
        raise DocumentInvalidError(log_context={"reason": "content_length_negative"})
    if declared > limit:
        raise DocumentTooLargeError(
            log_context={"reason": "declared_length_over_limit", "limit": limit}
        )


def enforce_streamed_length(*, received: int, limit: int) -> None:
    """Reject once the real byte count passes the limit.

    Raises:
        DocumentTooLargeError: more bytes arrived than the limit allows.
    """
    if received > limit:
        raise DocumentTooLargeError(
            log_context={"reason": "streamed_length_over_limit", "limit": limit}
        )


def _extension_of(filename: str) -> str:
    suffix = PurePosixPath(filename).suffix.lower()
    if not suffix:
        raise DocumentTypeUnsupportedError(log_context={"reason": "filename_has_no_extension"})
    return suffix


__all__ = [
    "MAGIC_SNIFF_BYTES",
    "MAX_FILENAME_CHARS",
    "enforce_declared_length",
    "enforce_streamed_length",
    "normalize_filename",
    "resolve_content_type",
    "verify_magic",
]
