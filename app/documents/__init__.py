"""Secure document storage.

Uploaded documents are Restricted data (``docs/data-classification.md``). They
are sealed with per-document keys bound to tenant, user, and document
(ADR-0021), held in S3-compatible object storage (ADR-0020, ADR-0027), and
described in PostgreSQL by metadata that never includes their contents.

This package stores documents and nothing more. Extraction, detection,
tokenization, and restoration are later phases.
"""

from app.documents.crypto import DocumentCipher, DocumentHeader, DocumentIdentity
from app.documents.models import (
    SUPPORTED_CONTENT_TYPES,
    Document,
    DocumentMetadata,
    DocumentStatus,
)
from app.documents.protocol import DocumentStore
from app.documents.repository import DocumentRepository, SqlAlchemyDocumentRepository
from app.documents.service import DocumentService

__all__ = [
    "SUPPORTED_CONTENT_TYPES",
    "Document",
    "DocumentCipher",
    "DocumentHeader",
    "DocumentIdentity",
    "DocumentMetadata",
    "DocumentRepository",
    "DocumentService",
    "DocumentStatus",
    "DocumentStore",
    "SqlAlchemyDocumentRepository",
]
