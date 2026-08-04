"""Bearer credential parsing and principal construction.

Two properties define this module.

**Indistinguishability.** Once a caller has presented *something* in the
``Authorization`` header, every way that credential can fail -- unsupported
scheme, malformed value, unknown prefix, wrong secret, expired key, revoked key,
even a database outage -- produces the byte-identical response: HTTP 401 with
``AUTHENTICATION_FAILED`` and its catalog message. A caller cannot probe which
prefixes exist, cannot learn that a key was once valid, and cannot tell an
outage from a bad key. The one distinguishable case is a *missing* header, which
answers ``AUTHENTICATION_REQUIRED``: it tells the caller only what the caller
already knew (they sent no credential), it leaks nothing about the key space,
and it is the response RFC 7235 expects from a protected resource.

**Silence.** The supplied credential is never logged, never placed in an
exception, never used as a metric label, and never stored on ``Principal``.
``BearerCredential`` exists to make that hard to get wrong: its ``repr`` is a
constant, and reading the value requires calling ``reveal()`` explicitly.

Key verification itself lives in ``app.repositories.api_keys``. This module
calls ``ApiKeyAuthenticator.authenticate`` -- which spends a digest even on a
prefix miss, so an unknown key costs the same work as a wrong secret -- and adds
nothing to either path that would reintroduce a timing difference.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, NoReturn

from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError

from app.auth import metrics
from app.db.base import utc_now
from app.db.models import API_KEY_STATUS_ACTIVE, ApiKey
from app.domain.errors import AuthenticationError, ErrorCode
from app.domain.models import Principal, Scope
from app.repositories.api_keys import ApiKeyAuthenticator

logger = logging.getLogger("app.auth")

AUTHORIZATION_HEADER: Final = "Authorization"
BEARER_SCHEME: Final = "bearer"

MAX_CREDENTIAL_CHARS: Final = 512
"""Anything longer is not one of our keys (they are ~55 characters).

Bounding the length bounds the work an unauthenticated caller can make the
digest step do.
"""


@dataclass(frozen=True, slots=True)
class BearerCredential:
    """A presented credential. Opaque by construction.

    ``reveal()`` is the only way out, so every call site that touches the secret
    is greppable, and an accidental ``repr``, f-string, or log field yields a
    constant instead of the key.
    """

    _value: str

    def reveal(self) -> str:
        """Return the raw credential. Only the authenticator may call this."""
        return self._value

    def __repr__(self) -> str:
        return "BearerCredential(***)"

    def __str__(self) -> str:
        return "BearerCredential(***)"


def _fail(
    outcome: str, *, reason: str, code: ErrorCode = ErrorCode.AUTHENTICATION_FAILED
) -> NoReturn:
    """Record the outcome and raise the public error.

    ``reason`` is a fixed identifier chosen from this module's source, never
    caller data, so it is safe both as a log field and in ``log_context``.
    """
    metrics.record_authentication(outcome)
    logger.info(
        "authentication_failed",
        extra={"error_code": code.value, "reason": reason},
    )
    raise AuthenticationError(code=code, log_context={"reason": reason})


def parse_bearer_credential(header_value: str | None) -> BearerCredential:
    """Extract the credential from an ``Authorization`` header value.

    Raises:
        AuthenticationError: the header is absent, uses another scheme, or does
            not carry a single well-formed token.
    """
    if header_value is None or not header_value.strip():
        _fail(
            metrics.AUTH_OUTCOME_MISSING_CREDENTIAL,
            reason="missing_authorization_header",
            code=ErrorCode.AUTHENTICATION_REQUIRED,
        )

    scheme, separator, remainder = header_value.strip().partition(" ")
    if not separator or scheme.lower() != BEARER_SCHEME:
        _fail(metrics.AUTH_OUTCOME_UNSUPPORTED_SCHEME, reason="unsupported_scheme")

    candidate = remainder.strip()
    if not candidate or len(candidate) > MAX_CREDENTIAL_CHARS or not _is_token(candidate):
        _fail(metrics.AUTH_OUTCOME_MALFORMED_CREDENTIAL, reason="malformed_credential")

    return BearerCredential(candidate)


def _is_token(value: str) -> bool:
    """Whether ``value`` is a single run of printable, non-space ASCII."""
    return all(0x21 <= ord(char) <= 0x7E for char in value)


async def resolve_principal(
    credential: BearerCredential,
    *,
    authenticator: ApiKeyAuthenticator,
    pepper: SecretStr,
    now: datetime | None = None,
) -> Principal:
    """Verify a credential and build the immutable ``Principal`` it authorizes.

    The status and expiry checks below duplicate what a correct
    ``ApiKeyAuthenticator`` already does. That is deliberate: authorization must
    not depend on a collaborator remembering to enforce them, and the duplicate
    check costs one comparison on a path that has already spent an HMAC.

    Raises:
        AuthenticationError: for every failure, with one public message.
    """
    moment = now or utc_now()

    try:
        record = await authenticator.authenticate(credential.reveal(), pepper=pepper)
    except (SQLAlchemyError, OSError) as exc:
        # Fail closed: an unreachable key store means we cannot establish who is
        # calling, so nobody is. The caller sees the same 401 as a bad key.
        logger.warning(
            "authentication_backend_unavailable",
            extra={"reason": "key_store_unavailable"},
        )
        metrics.record_authentication(metrics.AUTH_OUTCOME_BACKEND_UNAVAILABLE)
        raise AuthenticationError(log_context={"reason": "key_store_unavailable"}) from exc

    if record is None:
        # Covers unknown prefix and wrong secret. The authenticator cannot tell
        # us which, and must not.
        _fail(metrics.AUTH_OUTCOME_INVALID_CREDENTIAL, reason="invalid_credential")

    if record.status != API_KEY_STATUS_ACTIVE:
        _fail(metrics.AUTH_OUTCOME_REVOKED_CREDENTIAL, reason="invalid_credential")

    if record.expires_at is not None and record.expires_at <= moment:
        _fail(metrics.AUTH_OUTCOME_EXPIRED_CREDENTIAL, reason="invalid_credential")

    principal = build_principal(record)
    metrics.record_authentication(metrics.AUTH_OUTCOME_SUCCESS)
    # Identifiers only. The key *prefix* is a substring of the credential, so
    # even though it is non-secret by design it is kept out of log records: the
    # api key id names the same row without quoting any part of the key.
    logger.debug(
        "authentication_succeeded",
        extra={
            "tenant_id": str(principal.tenant_id),
            "api_key_id": str(principal.api_key_id),
        },
    )
    return principal


def build_principal(record: ApiKey) -> Principal:
    """Project a key record onto the immutable request principal.

    ``Principal`` has no field that can hold a credential, and the ``frozenset``
    of scopes cannot be widened after construction.
    """
    return Principal(
        tenant_id=record.tenant_id,
        api_key_id=record.id,
        api_key_prefix=record.prefix,
        scopes=parse_scopes(record.scopes),
    )


def parse_scopes(raw_scopes: Sequence[str]) -> frozenset[Scope]:
    """Convert stored scope strings into known ``Scope`` members.

    An unrecognized string is dropped rather than rejected: a key written by a
    newer version of the gateway must still authenticate here, and dropping is
    the fail-closed direction -- an unknown string grants nothing.
    """
    known: set[Scope] = set()
    for value in raw_scopes:
        try:
            known.add(Scope(value))
        except ValueError:
            logger.debug("unknown_scope_ignored", extra={"reason": "unknown_scope"})
    return frozenset(known)


async def authenticate_bearer(
    header_value: str | None,
    *,
    authenticator: ApiKeyAuthenticator,
    pepper: SecretStr,
    now: datetime | None = None,
) -> Principal:
    """Parse and verify in one step. The whole authentication path."""
    credential = parse_bearer_credential(header_value)
    return await resolve_principal(credential, authenticator=authenticator, pepper=pepper, now=now)
