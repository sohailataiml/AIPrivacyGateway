"""HTTP error envelope and the handlers that produce it.

Every failure leaves the gateway in the same shape:

```json
{"error": {"code": "VAULT_UNAVAILABLE", "message": "...", "request_id": "uuid"}}
```

The handlers never echo request content. Pydantic validation errors are the
sharp edge here -- their default representation includes the offending input,
which for this service could be a prompt containing exactly the data we exist to
protect. ``validation_exception_handler`` therefore reports field locations
only, never values.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.domain.errors import ERROR_CATALOG, ErrorCode, GatewayError
from app.observability.logging import get_logger

logger = get_logger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

# Applied to every error response: an error must never be cached, and the
# security headers must not depend on the happy path having run.
ERROR_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: ErrorCode
    message: str
    request_id: str | None = None


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ErrorBody


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return str(value) if value else None


def error_response(
    *,
    code: ErrorCode,
    request: Request,
    message: str | None = None,
    status_code: int | None = None,
) -> JSONResponse:
    """Build the canonical error response for a code."""
    catalog_status, catalog_message = ERROR_CATALOG[code]
    envelope = ErrorEnvelope(
        error=ErrorBody(
            code=code,
            message=message or catalog_message,
            request_id=_request_id(request),
        )
    )
    return JSONResponse(
        status_code=status_code or int(catalog_status),
        content=envelope.model_dump(mode="json"),
        headers=dict(ERROR_HEADERS),
    )


async def gateway_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Render a domain error. Its public message is already safe."""
    # Starlette types handlers as taking a bare Exception. Narrow by isinstance
    # rather than assert -- asserts vanish under python -O.
    if not isinstance(exc, GatewayError):  # pragma: no cover - registration guarantees type
        return await unhandled_exception_handler(request, exc)

    logger.warning(
        "request_failed",
        error_code=exc.code.value,
        request_id=_request_id(request),
        path=request.url.path,
        method=request.method,
        status_code=exc.status_code,
        **exc.log_context,
    )
    return error_response(code=exc.code, request=request, message=exc.public_message)


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Report *where* validation failed, never *what* the caller sent."""
    if not isinstance(exc, RequestValidationError):  # pragma: no cover
        return await unhandled_exception_handler(request, exc)

    # errors() entries carry an "input" key holding the rejected value. Keeping
    # only the location and the error type is what makes this handler safe.
    locations = [".".join(str(part) for part in error["loc"]) for error in exc.errors()]

    logger.info(
        "request_invalid",
        error_code=ErrorCode.INVALID_REQUEST.value,
        request_id=_request_id(request),
        path=request.url.path,
        method=request.method,
        reason=";".join(sorted(set(locations))[:10]),
    )
    return error_response(code=ErrorCode.INVALID_REQUEST, request=request)


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Map Starlette HTTP errors onto the gateway envelope."""
    if not isinstance(exc, StarletteHTTPException):  # pragma: no cover
        return await unhandled_exception_handler(request, exc)

    code = _STATUS_TO_CODE.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
    catalog_message = ERROR_CATALOG[code][1]
    return error_response(
        code=code,
        request=request,
        message=catalog_message,
        status_code=exc.status_code,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last resort. The caller learns nothing beyond "it failed"."""
    # exc_info records the traceback for operators; the response body does not
    # include the exception text, which could contain request content.
    logger.error(
        "unhandled_exception",
        error_code=ErrorCode.INTERNAL_ERROR.value,
        request_id=_request_id(request),
        path=request.url.path,
        method=request.method,
        exc_info=exc,
    )
    return error_response(code=ErrorCode.INTERNAL_ERROR, request=request)


_STATUS_TO_CODE: dict[int, ErrorCode] = {
    400: ErrorCode.INVALID_REQUEST,
    401: ErrorCode.AUTHENTICATION_REQUIRED,
    403: ErrorCode.AUTHORIZATION_FAILED,
    404: ErrorCode.INVALID_REQUEST,
    405: ErrorCode.INVALID_REQUEST,
    413: ErrorCode.REQUEST_TOO_LARGE,
    422: ErrorCode.INVALID_REQUEST,
    429: ErrorCode.RATE_LIMIT_EXCEEDED,
    500: ErrorCode.INTERNAL_ERROR,
    502: ErrorCode.PROVIDER_UNAVAILABLE,
    503: ErrorCode.VAULT_UNAVAILABLE,
    504: ErrorCode.PROVIDER_TIMEOUT,
}


def register_exception_handlers(app: FastAPI) -> None:
    """Attach every handler. Order matters: most specific first."""
    handlers: list[tuple[Any, Any]] = [
        (GatewayError, gateway_error_handler),
        (RequestValidationError, validation_exception_handler),
        (StarletteHTTPException, http_exception_handler),
        (Exception, unhandled_exception_handler),
    ]
    for exception_type, handler in handlers:
        app.add_exception_handler(exception_type, handler)
