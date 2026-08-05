"""Object-storage adapters behind the ``DocumentStore`` seam."""

from app.documents.storage.fakes import FakeDocumentStore
from app.documents.storage.s3 import MIN_PART_BYTES, S3CompatibleDocumentStore

__all__ = ["MIN_PART_BYTES", "FakeDocumentStore", "S3CompatibleDocumentStore"]
