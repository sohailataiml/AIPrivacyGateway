"""Document storage endpoints.

Four routes, and the split between them is deliberate:

* ``POST /v1/documents`` accepts a file and stores it sealed.
* ``GET /v1/documents/{id}`` streams the plaintext back to its owner.
* ``GET /v1/documents/{id}/status`` answers from metadata alone -- no key is
  touched and no object is read, so a poller costs almost nothing and never
  causes a decryption.
* ``DELETE /v1/documents/{id}`` destroys the object and its row.

**Tenancy and identity come from the verified key, never from the request.**
``GET /v1/documents/<someone-else's-uuid>`` addresses this principal's own
namespace and finds nothing there, and even a row fetched in error would fail to
decrypt (ADR-0021).

**The response never contains a document's contents except on the download
route**, which streams bytes rather than embedding them in JSON. Metadata
responses carry the filename because it belongs to the caller who uploaded it,
and carry no storage key: an opaque key grants nothing, but publishing it also
buys the caller nothing.

Nothing here logs a filename or a byte of content.
"""

from __future__ import annotations

import urllib.parse
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Depends, File, Form, Path, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.errors import ErrorEnvelope
from app.auth.dependencies import require_scope
from app.documents.models import Document, DocumentMetadata, DocumentStatus
from app.documents.service import DocumentService
from app.domain.errors import DocumentInvalidError, ErrorCode, GatewayError
from app.domain.models import ChatMessage, Principal, PrivacySummary, Scope
from app.observability.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - import cycle-free typing only
    from collections.abc import AsyncIterator

    from app.api.composition import Services

logger = get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["documents"])

UPLOAD_CHUNK_BYTES = 65_536
"""Bytes read from the request per iteration. Never the whole file."""

DOCUMENT_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_400_BAD_REQUEST: {
        "model": ErrorEnvelope,
        "description": "`DOCUMENT_INVALID` -- filename or body failed validation",
    },
    status.HTTP_401_UNAUTHORIZED: {
        "model": ErrorEnvelope,
        "description": "`AUTHENTICATION_REQUIRED`, `AUTHENTICATION_FAILED`",
    },
    status.HTTP_403_FORBIDDEN: {
        "model": ErrorEnvelope,
        "description": "`AUTHORIZATION_FAILED`",
    },
    status.HTTP_404_NOT_FOUND: {
        "model": ErrorEnvelope,
        "description": "`DOCUMENT_NOT_FOUND`",
    },
    status.HTTP_413_CONTENT_TOO_LARGE: {
        "model": ErrorEnvelope,
        "description": "`DOCUMENT_TOO_LARGE`, `REQUEST_TOO_LARGE`",
    },
    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE: {
        "model": ErrorEnvelope,
        "description": "`DOCUMENT_TYPE_UNSUPPORTED`",
    },
    status.HTTP_429_TOO_MANY_REQUESTS: {
        "model": ErrorEnvelope,
        "description": "`RATE_LIMIT_EXCEEDED`",
    },
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": ErrorEnvelope,
        "description": "`DOCUMENT_STORAGE_UNAVAILABLE`, `DOCUMENT_ENCRYPTION_FAILED`",
    },
}


class DocumentResponse(BaseModel):
    """A stored document, as its owner sees it.

    No storage key and no key id: both are internal, and neither helps a caller
    do anything the document id does not already allow.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID
    filename: str
    content_type: str
    byte_size: int = Field(description="Length of the original document in bytes.")
    sha256: str = Field(description="Checksum of the original document.")
    status: DocumentStatus
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_document(cls, document: Document) -> DocumentResponse:
        return cls(
            id=document.metadata.id,
            filename=document.filename,
            content_type=document.metadata.content_type,
            byte_size=document.metadata.byte_size,
            sha256=document.metadata.sha256_hex,
            status=document.metadata.status,
            created_at=document.metadata.created_at,
            updated_at=document.metadata.updated_at,
        )


class DocumentStatusResponse(BaseModel):
    """Metadata-only status. Deliberately carries no filename.

    Status is the cheap, pollable route; decrypting a filename to answer it
    would mean touching key material on every poll for information the caller
    did not ask for.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID
    status: DocumentStatus
    content_type: str
    byte_size: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_metadata(cls, metadata: DocumentMetadata) -> DocumentStatusResponse:
        return cls(
            id=metadata.id,
            status=metadata.status,
            content_type=metadata.content_type,
            byte_size=metadata.byte_size,
            created_at=metadata.created_at,
            updated_at=metadata.updated_at,
        )


@router.post(
    "/documents",
    status_code=status.HTTP_201_CREATED,
    response_model=DocumentResponse,
    summary="Upload and store a document, encrypted",
    response_description="The stored document's metadata.",
    responses=DOCUMENT_ERROR_RESPONSES,
)
async def upload_document(
    http_request: Request,
    principal: Annotated[Principal, Depends(require_scope(Scope.DOCUMENTS_WRITE))],
    file: Annotated[UploadFile, File(description="The document. TXT, PDF, or DOCX.")],
    filename: Annotated[
        str | None,
        Form(description="Overrides the filename from the multipart part."),
    ] = None,
) -> DocumentResponse:
    """Store one document under the calling principal.

    The body is streamed: it is validated, hashed, sealed, and uploaded in one
    pass, so a 25 MiB document costs one chunk of memory rather than 25 MiB of
    it. Nothing is retained if any step fails.
    """
    documents = _documents(http_request)
    chosen = filename or file.filename
    if not chosen:
        # Nothing to validate and nothing to name the document with.
        raise DocumentInvalidError(log_context={"reason": "filename_missing"})

    document = await documents.store(
        tenant_id=principal.tenant_id,
        user_id=_user_id(principal),
        filename=chosen,
        declared_content_type=file.content_type,
        declared_length=_declared_length(http_request),
        source=_stream(file),
    )
    return DocumentResponse.from_document(document)


@router.get(
    "/documents/{document_id}",
    summary="Download a stored document",
    response_description="The original bytes, streamed.",
    responses=DOCUMENT_ERROR_RESPONSES,
    response_class=StreamingResponse,
)
async def download_document(
    http_request: Request,
    document_id: Annotated[UUID, Path(description="The document to retrieve.")],
    principal: Annotated[Principal, Depends(require_scope(Scope.DOCUMENTS_READ))],
) -> StreamingResponse:
    """Stream the document's plaintext back to its owner.

    Metadata is resolved before the response begins, so a missing document is a
    clean ``404`` rather than a ``200`` that fails part-way. Every chunk is
    authenticated as it is read.
    """
    document, chunks = await _documents(http_request).open(
        tenant_id=principal.tenant_id,
        user_id=_user_id(principal),
        document_id=document_id,
    )
    return StreamingResponse(
        chunks,
        media_type=document.metadata.content_type,
        headers={
            "Content-Length": str(document.metadata.byte_size),
            # RFC 5987 encoding: a filename may hold non-ASCII characters, and
            # a raw one in a header is a response-splitting risk.
            "Content-Disposition": _content_disposition(document.filename),
            # Restricted content must not be cached by a proxy or a browser.
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/documents/{document_id}/status",
    response_model=DocumentStatusResponse,
    summary="Check a document's storage status",
    response_description="Metadata only. No key material is used.",
    responses=DOCUMENT_ERROR_RESPONSES,
)
async def document_status(
    http_request: Request,
    document_id: Annotated[UUID, Path(description="The document to inspect.")],
    principal: Annotated[Principal, Depends(require_scope(Scope.DOCUMENTS_READ))],
) -> DocumentStatusResponse:
    metadata = await _documents(http_request).status(
        tenant_id=principal.tenant_id,
        user_id=_user_id(principal),
        document_id=document_id,
    )
    return DocumentStatusResponse.from_metadata(metadata)


@router.delete(
    "/documents/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Destroy a stored document",
    response_description="The document is gone, whether or not it ever existed.",
    responses=DOCUMENT_ERROR_RESPONSES,
)
async def delete_document(
    http_request: Request,
    document_id: Annotated[UUID, Path(description="The document to destroy.")],
    principal: Annotated[Principal, Depends(require_scope(Scope.DOCUMENTS_DELETE))],
) -> None:
    """Delete the object and its metadata.

    Answers ``204`` whether the document existed or not, for the same reason
    session deletion does: a different answer for "never existed" would make
    this an oracle for which document ids are real.
    """
    await _documents(http_request).delete(
        tenant_id=principal.tenant_id,
        user_id=_user_id(principal),
        document_id=document_id,
    )


def _documents(http_request: Request) -> DocumentService:
    """Return the document service, or refuse clearly.

    The routes are not mounted when ``DOCUMENTS_ENABLED`` is false, so reaching
    here with no service means the app was assembled inconsistently. Failing
    loudly beats an ``AttributeError`` rendered as an unexplained 500.
    """
    services: Services = http_request.app.state.services
    if services.documents is None:  # pragma: no cover - routes are absent then
        raise GatewayError(
            code=ErrorCode.INTERNAL_ERROR,
            log_context={"reason": "document_service_not_configured"},
        )
    return services.documents


def _user_id(principal: Principal) -> UUID:
    """The authenticated subject a document is bound to.

    The gateway authenticates API keys rather than people, so the key id is the
    subject. When a user model arrives this is the single place that changes.
    """
    return principal.api_key_id


def _declared_length(request: Request) -> int | None:
    raw = request.headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


async def _stream(file: UploadFile) -> AsyncIterator[bytes]:
    """Yield the uploaded body in fixed-size pieces."""
    while chunk := await file.read(UPLOAD_CHUNK_BYTES):
        yield chunk


def _content_disposition(filename: str) -> str:
    quoted = urllib.parse.quote(filename, safe="")
    return f"attachment; filename*=UTF-8''{quoted}"


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------
class ProcessDocumentRequest(BaseModel):
    """What to do with a stored document, and where to send it.

    There is no field here for a tenant, a user, a session, or a policy. Those
    come from the verified key and from server-side configuration, which is what
    stops a caller from addressing another principal's document or asking for a
    policy they would prefer.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    instruction: str = Field(min_length=1, max_length=4_000)
    """What the caller wants done. Sent as a system message, separate from the
    document, and **not** tokenized -- see ``app/documents/pipeline.py``."""

    session_id: UUID | None = None
    """The session the vault mappings belong to.

    Optional, and a new session is minted when it is absent. Supplying one is
    how a caller has a document's tokens resolve in the same session as the
    conversation that will quote them.
    """


class ProcessDocumentResponse(BaseModel):
    """The restored answer plus counts. Returned only to the request principal."""

    model_config = ConfigDict(extra="forbid")

    request_id: UUID
    session_id: UUID
    document_id: UUID
    provider: str
    model: str
    message: ChatMessage
    privacy: PrivacySummary
    outbound_attestation: str
    """Keyed digest of the exact bytes sent upstream (ADR-0024).

    A digest, never the payload. It lets a caller who retained the payload prove
    afterwards what was transmitted, without the gateway having stored it.
    """


@router.post(
    "/documents/{document_id}/process",
    response_model=ProcessDocumentResponse,
    status_code=status.HTTP_200_OK,
    summary="Send a stored document through the privacy pipeline to a model",
    response_description="The restored answer plus a privacy summary of counts only.",
    responses=DOCUMENT_ERROR_RESPONSES,
)
async def process_document(
    http_request: Request,
    payload: Annotated[ProcessDocumentRequest, Body()],
    principal: Annotated[Principal, Depends(require_scope(Scope.DOCUMENTS_READ))],
    _chat: Annotated[Principal, Depends(require_scope(Scope.CHAT_INVOKE))],
    document_id: Annotated[UUID, Path(description="Identifier returned by the upload route.")],
) -> ProcessDocumentResponse:
    """Decrypt, extract, detect, protect, send, and restore, in that order.

    **Two scopes, both required.** Processing reads a document *and* invokes a
    model, so it needs `documents:read` and `chat:invoke`. A key that may read
    documents but not call a provider cannot use this route to do so
    indirectly, and neither can one holding the reverse.

    The provider never sees an original: every span the policy acts on is
    replaced before serialisation, and a scan runs over the exact bytes to be
    sent. A finding there refuses the request rather than warning about it.
    """
    services: Services = http_request.app.state.services
    if services.document_pipeline is None:  # pragma: no cover - route absent then
        raise GatewayError(
            code=ErrorCode.INTERNAL_ERROR,
            log_context={"reason": "document_pipeline_not_configured"},
        )

    answer = await services.document_pipeline.run(
        principal=principal,
        request_id=_request_id(http_request),
        session_id=payload.session_id or uuid4(),
        user_id=_user_id(principal),
        document_id=document_id,
        provider=payload.provider,
        model=payload.model,
        instruction=payload.instruction,
    )
    return ProcessDocumentResponse(
        request_id=answer.request_id,
        session_id=answer.session_id,
        document_id=answer.document_id,
        provider=answer.provider,
        model=answer.model,
        message=ChatMessage(role="assistant", content=answer.text),
        privacy=answer.privacy,
        outbound_attestation=answer.outbound_hmac,
    )


def _request_id(http_request: Request) -> UUID:
    """The correlation id the middleware already assigned, or a fresh one.

    Reusing the middleware's id means the audit row, the log lines, and the
    ``X-Request-ID`` header a caller sees all name the same request.
    """
    existing = getattr(http_request.state, "request_id", None)
    if isinstance(existing, UUID):
        return existing
    if isinstance(existing, str):
        try:
            return UUID(existing)
        except ValueError:
            return uuid4()
    return uuid4()
