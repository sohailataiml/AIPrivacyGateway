"""Request-scoped middleware.

Four concerns, in the order they must run:

1. ``RequestIdMiddleware`` assigns the correlation id everything downstream logs.
2. ``MetricsMiddleware`` counts and times every request, including the ones the
   layers below reject.
3. ``BodySizeLimitMiddleware`` rejects oversized bodies *before* detection,
   tokenization, or a provider call can spend time on them.
4. ``SecurityHeadersMiddleware`` sets the headers that must be present on every
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
from app.observability import metrics
from app.observability.logging import get_logger

logger = get_logger(__name__)

CONTENT_LENGTH_HEADER = "content-length"
HTTP_INTERNAL_SERVER_ERROR = 500

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


class MetricsMiddleware(BaseHTTPMiddleware):
    """Count and time every request, labelled by route template.

    Registered outside ``BodySizeLimitMiddleware`` so a rejected oversized body
    still shows up as a request -- a spike of 413s is exactly the signal an
    operator needs, and it would be invisible from inside that layer.

    The route template is read *after* ``call_next`` returns, because that is
    when the router has matched. Reading ``request.url.path`` instead would put
    a caller-controlled string into a label; see ``app.observability.metrics``
    for why that is the one thing this must not do.
    """

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        started = time.perf_counter()
        status_code = HTTP_INTERNAL_SERVER_ERROR
        with metrics.track_in_flight():
            try:
                response = await call_next(request)
            except Exception:
                # An exception escaping the handler chain is still a request
                # that happened, and it is the one an operator most wants
                # counted. Record it as a 500 -- which is what the exception
                # handlers will turn it into -- then let it propagate.
                _record(request, status=status_code, started=started)
                raise
            status_code = response.status_code
            _record(request, status=status_code, started=started)
            return response


def _record(request: Request, *, status: int, started: float) -> None:
    """Emit the HTTP metrics for one finished request."""
    metrics.observe_request(
        method=request.method,
        route=_route_template(request),
        status=status,
        duration_seconds=metrics.elapsed_since(started),
    )


def _route_template(request: Request) -> str | None:
    """Return the matched route's path template, or ``None`` if nothing matched.

    ``getattr`` rather than attribute access: ``scope["route"]`` is a Starlette
    ``Mount`` or ``WebSocketRoute`` in some configurations, and neither is
    guaranteed to expose ``path``.
    """
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else None


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

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_bytes: int,
        upload_max_bytes: int | None = None,
        upload_path_prefixes: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        # Uploads need a far larger ceiling than JSON does. Raising the single
        # global limit to suit them would let every other endpoint accept a
        # multi-megabyte body it has no use for, so the exemption is scoped to
        # the paths that actually carry files.
        self.upload_max_bytes = upload_max_bytes if upload_max_bytes is not None else max_bytes
        self.upload_path_prefixes = upload_path_prefixes

    def limit_for(self, path: str) -> int:
        """Return the byte ceiling that applies to ``path``."""
        if any(path.startswith(prefix) for prefix in self.upload_path_prefixes):
            return self.upload_max_bytes
        return self.max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        limit = self.limit_for(request.url.path)

        declared = request.headers.get(CONTENT_LENGTH_HEADER)
        if declared is not None:
            try:
                if int(declared) > limit:
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
                if received > limit:
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
