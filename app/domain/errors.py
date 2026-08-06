"""Domain errors and their stable machine-readable codes.

Two rules govern everything in this module:

1. Every error carries a *public* message that is safe to return verbatim to an
   unauthenticated caller. It never names a host, a credential, a detected
   value, or an internal component version.
2. Failure is closed. Any code that means "privacy processing could not be
   completed" maps to a status that stops the request; there is no error here
   that a caller can trigger to skip detection, tokenization, or the vault.

Codes are contract. Renaming one is a breaking API change.
"""

from __future__ import annotations

from enum import StrEnum
from http import HTTPStatus
from typing import Any, Final


class ErrorCode(StrEnum):
    """Stable machine-readable error identifiers returned to clients."""

    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    INVALID_REQUEST = "INVALID_REQUEST"
    UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"
    POLICY_NOT_FOUND = "POLICY_NOT_FOUND"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ENTITY_LIMIT_EXCEEDED = "ENTITY_LIMIT_EXCEEDED"
    PRIVACY_DETECTOR_UNAVAILABLE = "PRIVACY_DETECTOR_UNAVAILABLE"
    VAULT_UNAVAILABLE = "VAULT_UNAVAILABLE"
    VAULT_ENCRYPTION_FAILED = "VAULT_ENCRYPTION_FAILED"
    PROVIDER_NOT_ALLOWED = "PROVIDER_NOT_ALLOWED"
    MODEL_NOT_ALLOWED = "MODEL_NOT_ALLOWED"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_RESPONSE_INVALID = "PROVIDER_RESPONSE_INVALID"
    RESTORATION_FAILED = "RESTORATION_FAILED"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    DOCUMENT_NOT_FOUND = "DOCUMENT_NOT_FOUND"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_TYPE_UNSUPPORTED = "DOCUMENT_TYPE_UNSUPPORTED"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_STORAGE_UNAVAILABLE = "DOCUMENT_STORAGE_UNAVAILABLE"
    DOCUMENT_ENCRYPTION_FAILED = "DOCUMENT_ENCRYPTION_FAILED"
    DOCUMENT_EXTRACTION_FAILED = "DOCUMENT_EXTRACTION_FAILED"
    DOCUMENT_EXTRACTION_TIMEOUT = "DOCUMENT_EXTRACTION_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# One HTTP status and one safe public message per code.
#
# Authentication and authorization deliberately share wording across distinct
# failure reasons so a caller cannot probe for which key prefixes exist.
ERROR_CATALOG: Final[dict[ErrorCode, tuple[HTTPStatus, str]]] = {
    ErrorCode.AUTHENTICATION_REQUIRED: (
        HTTPStatus.UNAUTHORIZED,
        "Authentication is required.",
    ),
    ErrorCode.AUTHENTICATION_FAILED: (
        HTTPStatus.UNAUTHORIZED,
        "The provided credentials are not valid.",
    ),
    ErrorCode.AUTHORIZATION_FAILED: (
        HTTPStatus.FORBIDDEN,
        "The credentials do not grant access to this operation.",
    ),
    ErrorCode.RATE_LIMIT_EXCEEDED: (
        HTTPStatus.TOO_MANY_REQUESTS,
        "The request rate limit has been exceeded.",
    ),
    ErrorCode.REQUEST_TOO_LARGE: (
        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        "The request body exceeds the configured limit.",
    ),
    ErrorCode.INVALID_REQUEST: (
        HTTPStatus.BAD_REQUEST,
        "The request is not valid.",
    ),
    ErrorCode.UNSUPPORTED_LANGUAGE: (
        HTTPStatus.BAD_REQUEST,
        "The requested language is not supported.",
    ),
    ErrorCode.POLICY_NOT_FOUND: (
        HTTPStatus.CONFLICT,
        "No active privacy policy is configured.",
    ),
    ErrorCode.POLICY_VIOLATION: (
        HTTPStatus.UNPROCESSABLE_ENTITY,
        "The request was blocked by the active privacy policy.",
    ),
    ErrorCode.ENTITY_LIMIT_EXCEEDED: (
        HTTPStatus.UNPROCESSABLE_ENTITY,
        "The request contains more sensitive values than the policy allows.",
    ),
    ErrorCode.PRIVACY_DETECTOR_UNAVAILABLE: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        "The privacy detection service is unavailable.",
    ),
    ErrorCode.VAULT_UNAVAILABLE: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        "The secure mapping service is unavailable.",
    ),
    ErrorCode.VAULT_ENCRYPTION_FAILED: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        "The secure mapping service could not complete the operation.",
    ),
    ErrorCode.PROVIDER_NOT_ALLOWED: (
        HTTPStatus.FORBIDDEN,
        "The requested provider is not permitted.",
    ),
    ErrorCode.MODEL_NOT_ALLOWED: (
        HTTPStatus.FORBIDDEN,
        "The requested model is not permitted.",
    ),
    ErrorCode.PROVIDER_TIMEOUT: (
        HTTPStatus.GATEWAY_TIMEOUT,
        "The upstream model provider did not respond in time.",
    ),
    ErrorCode.PROVIDER_UNAVAILABLE: (
        HTTPStatus.BAD_GATEWAY,
        "The upstream model provider is unavailable.",
    ),
    ErrorCode.PROVIDER_RESPONSE_INVALID: (
        HTTPStatus.BAD_GATEWAY,
        "The upstream model provider returned an unusable response.",
    ),
    ErrorCode.RESTORATION_FAILED: (
        HTTPStatus.INTERNAL_SERVER_ERROR,
        "The response could not be securely restored.",
    ),
    ErrorCode.AUDIT_UNAVAILABLE: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        "The audit service is unavailable.",
    ),
    ErrorCode.DOCUMENT_NOT_FOUND: (
        HTTPStatus.NOT_FOUND,
        "No such document.",
    ),
    ErrorCode.DOCUMENT_TOO_LARGE: (
        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        "The document exceeds the configured size limit.",
    ),
    ErrorCode.DOCUMENT_TYPE_UNSUPPORTED: (
        HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        "The document type is not supported.",
    ),
    ErrorCode.DOCUMENT_INVALID: (
        HTTPStatus.BAD_REQUEST,
        "The document could not be accepted.",
    ),
    ErrorCode.DOCUMENT_STORAGE_UNAVAILABLE: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        "The document storage service is unavailable.",
    ),
    ErrorCode.DOCUMENT_ENCRYPTION_FAILED: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        "The document storage service could not complete the operation.",
    ),
    ErrorCode.DOCUMENT_EXTRACTION_FAILED: (
        # 422 rather than 500: the request was well formed and the file was
        # not. Saying so does not disclose anything about the file, because the
        # reason code never leaves the log.
        HTTPStatus.UNPROCESSABLE_ENTITY,
        "The document could not be read.",
    ),
    ErrorCode.DOCUMENT_EXTRACTION_TIMEOUT: (
        HTTPStatus.SERVICE_UNAVAILABLE,
        "The document could not be read in the time allowed.",
    ),
    ErrorCode.INTERNAL_ERROR: (
        HTTPStatus.INTERNAL_SERVER_ERROR,
        "An internal error occurred.",
    ),
}


class GatewayError(Exception):
    """Base class for every error the gateway converts into an API response.

    ``log_context`` holds non-sensitive structured detail for operators. Callers
    must never place message content, detected values, tokens, or credentials in
    it -- the logging pipeline emits it verbatim.
    """

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(
        self,
        message: str | None = None,
        *,
        code: ErrorCode | None = None,
        log_context: dict[str, Any] | None = None,
    ) -> None:
        if code is not None:
            self.code = code
        self.public_message = message or ERROR_CATALOG[self.code][1]
        self.log_context = log_context or {}
        # The exception string is the public message: even an accidental
        # ``str(exc)`` in a log line stays safe.
        super().__init__(self.public_message)

    @property
    def status_code(self) -> int:
        return int(ERROR_CATALOG[self.code][0])


class AuthenticationError(GatewayError):
    code = ErrorCode.AUTHENTICATION_FAILED


class AuthorizationError(GatewayError):
    code = ErrorCode.AUTHORIZATION_FAILED


class RateLimitExceededError(GatewayError):
    code = ErrorCode.RATE_LIMIT_EXCEEDED


class RequestTooLargeError(GatewayError):
    code = ErrorCode.REQUEST_TOO_LARGE


class InvalidRequestError(GatewayError):
    code = ErrorCode.INVALID_REQUEST


class PolicyNotFoundError(GatewayError):
    code = ErrorCode.POLICY_NOT_FOUND


class PolicyViolationError(GatewayError):
    """Raised when policy blocks the request. Never carries the blocked value."""

    code = ErrorCode.POLICY_VIOLATION


class EntityLimitExceededError(GatewayError):
    code = ErrorCode.ENTITY_LIMIT_EXCEEDED


class DetectorUnavailableError(GatewayError):
    code = ErrorCode.PRIVACY_DETECTOR_UNAVAILABLE


class VaultUnavailableError(GatewayError):
    code = ErrorCode.VAULT_UNAVAILABLE


class VaultEncryptionError(GatewayError):
    code = ErrorCode.VAULT_ENCRYPTION_FAILED


class DocumentNotFoundError(GatewayError):
    """Raised for a document this tenant and user cannot address.

    Deliberately the same answer whether the document never existed, was
    deleted, or belongs to somebody else -- distinguishing them would make the
    endpoint an oracle for which document ids exist.
    """

    code = ErrorCode.DOCUMENT_NOT_FOUND


class DocumentTooLargeError(GatewayError):
    code = ErrorCode.DOCUMENT_TOO_LARGE


class DocumentTypeUnsupportedError(GatewayError):
    code = ErrorCode.DOCUMENT_TYPE_UNSUPPORTED


class DocumentInvalidError(GatewayError):
    """A filename, declared type, or byte stream that failed validation."""

    code = ErrorCode.DOCUMENT_INVALID


class DocumentStorageUnavailableError(GatewayError):
    code = ErrorCode.DOCUMENT_STORAGE_UNAVAILABLE


class DocumentEncryptionError(GatewayError):
    code = ErrorCode.DOCUMENT_ENCRYPTION_FAILED


class DocumentExtractionError(GatewayError):
    """The document could not be parsed into text.

    Covers a corrupt file, an encrypted PDF, a decompression bomb, and a
    document whose extracted text exceeds the configured ceiling. They share a
    code deliberately: the distinction matters to an operator reading the
    reason in a log, and telling a caller which one it was describes the file
    back to whoever supplied it.
    """

    code = ErrorCode.DOCUMENT_EXTRACTION_FAILED


class DocumentExtractionTimeoutError(GatewayError):
    """Extraction exceeded its wall-clock budget and the worker was killed.

    Separate from ``DocumentExtractionError`` because the remedies differ: a
    parse failure is about the file, a timeout is about capacity or a parser
    that does not terminate.
    """

    code = ErrorCode.DOCUMENT_EXTRACTION_TIMEOUT


class ProviderNotAllowedError(GatewayError):
    code = ErrorCode.PROVIDER_NOT_ALLOWED


class ModelNotAllowedError(GatewayError):
    code = ErrorCode.MODEL_NOT_ALLOWED


class ProviderTimeoutError(GatewayError):
    code = ErrorCode.PROVIDER_TIMEOUT


class ProviderUnavailableError(GatewayError):
    code = ErrorCode.PROVIDER_UNAVAILABLE


class ProviderResponseInvalidError(GatewayError):
    code = ErrorCode.PROVIDER_RESPONSE_INVALID


class RestorationError(GatewayError):
    code = ErrorCode.RESTORATION_FAILED


class AuditUnavailableError(GatewayError):
    code = ErrorCode.AUDIT_UNAVAILABLE


class UnsupportedLanguageError(GatewayError):
    code = ErrorCode.UNSUPPORTED_LANGUAGE
