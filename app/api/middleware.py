"""Request-scoped middleware.

Three concerns, in the order they must run:

1. ``RequestIdMiddleware`` assigns the correlation id everything downstream logs.
2. ``BodySizeLimitMiddleware`` rejects oversized bodies *before* detection,
   tokenization, or a provider call can spend time on them.
3. ``SecurityHeadersMiddleware`` sets the headers that must be present on every
   response including error responses.

A caller-supplied ``X-Request-ID`` is deliberately not trusted as-is: it is
accepted only when it parses as a UUID, so the value cannot be used to inject
arbitrary text into log records.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from uuid import UUID, uuid4

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import REQUEST_ID_HEADER, error_response
from app.domain.errors import ErrorCode
from app.observability.logging import get_logger

logger = get_logger(__name__)

CONTENT_LENGTH_HEADER = "content-length"

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

RequestHandler = Callable[[Request], Awaitable[Response]]


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Bind a request id to the log context and echo it on the response."""

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        request_id = _incoming_request_id(request) or uuid4()
        request.state.request_id = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=str(request_id))

        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.bind_contextvars(
                duration_ms=round((time.perf_counter() - started) * 1000, 2)
            )

        response.headers[REQUEST_ID_HEADER] = str(request_id)
        return response


def _incoming_request_id(request: Request) -> UUID | None:
    """Accept a caller-supplied id only if it is a well-formed UUID."""
    raw = request.headers.get(REQUEST_ID_HEADER)
    if not raw:
        return None
    try:
        return UUID(raw)
    except ValueError:
        return None


class BodySizeLimitMiddleware:
    """Reject bodies over the configured limit before any expensive work.

    This is raw ASGI rather than ``BaseHTTPMiddleware`` on purpose. Trusting
    ``Content-Length`` alone is a bypass: a chunked request omits the header
    entirely, so the declared-size check would wave through a body of any size.
    Counting bytes as they arrive closes that, and short-circuits as soon as the
    limit is passed rather than buffering the whole payload first.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        declared = request.headers.get(CONTENT_LENGTH_HEADER)
        if declared is not None:
            try:
                if int(declared) > self.max_bytes:
                    await self._reject(ErrorCode.REQUEST_TOO_LARGE, request, send)
                    return
            except ValueError:
                # A malformed Content-Length is a malformed request, not a
                # reason to fall through and read an unbounded body.
                await self._reject(ErrorCode.INVALID_REQUEST, request, send)
                return

        received = 0
        exceeded = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    # Hand the app an empty terminal chunk. It will fail
                    # validation harmlessly; the response is replaced below.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        sent_start = False

        async def guarded_send(message: Message) -> None:
            nonlocal sent_start
            if exceeded and not sent_start:
                # The body blew the limit mid-stream. Discard whatever the app
                # produced and answer with the size error instead.
                await self._reject(ErrorCode.REQUEST_TOO_LARGE, request, send)
                sent_start = True
                return
            if exceeded:
                return
            if message["type"] == "http.response.start":
                sent_start = True
            await send(message)

        await self.app(scope, counting_receive, guarded_send)

    async def _reject(self, code: ErrorCode, request: Request, send: Send) -> None:
        logger.info(
            "request_rejected",
            error_code=code.value,
            path=request.url.path,
            method=request.method,
            reason="body_size_exceeded" if code is ErrorCode.REQUEST_TOO_LARGE else "malformed",
        )
        await error_response(code=code, request=request)(request.scope, _no_receive, send)


async def _no_receive() -> Message:  # pragma: no cover - responses do not read
    return {"type": "http.disconnect"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply security headers to every response."""

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response
