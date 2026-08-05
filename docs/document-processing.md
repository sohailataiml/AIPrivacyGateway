# Secure Document Processing

Extends the prompt pipeline to uploaded files. Not yet implemented — this is the
specification the implementation must satisfy.

## Pipeline

```text
Upload → Validate → Encrypt and store → Extract → Segment → Detect → Protect
      → Batch vault write → Outbound scan → LLM → Restore → Audit
```

The stages after `Detect` are the existing prompt pipeline. What document
processing adds is everything before it, plus segmentation.

## Storage

S3-compatible object storage, MinIO in the Compose and interview environment
(ADR-0027), reached through the S3 API only so the local store and a deployed
one differ by configuration rather than by code.
PostgreSQL stores metadata only — identifiers, content type, sizes, checksums,
timestamps, processing status — and never document bytes or extracted text
(ADR-0020).

Encrypt with a per-document data key and AES-256-GCM. Associated data includes
tenant, user, document, content type, and schema version, so a stored object
cannot be replayed into another context or reinterpreted under another schema
(ADR-0021).

## Extraction

CPU-bound extraction runs in a **bounded** worker pool. Unbounded extraction is
a denial-of-service vector: a handful of large uploads would starve the request
path.

Temporary plaintext files are deleted immediately, including on the error path.
Extracted text is Restricted data — see
[data-classification.md](data-classification.md) — and the default is not to
retain it.

## Offsets and references

Global offsets and page/segment references are preserved through extraction and
segmentation. Two things depend on this:

- **Correct protection.** A detected span must map back to the exact bytes it
  came from. An offset that drifts by one protects the wrong text.
- **Correct restoration.** Restored output must reassemble in the original
  order.

Segmentation exists because documents exceed model context windows and because
detection quality degrades on very long inputs. Segments must not split entities
across boundaries in a way that hides them from the detector — a boundary
falling mid-value is a fail-open condition.

## Vault interaction

A document produces far more entities than a prompt does. Mapping writes are
batched (ADR-0022); a per-token round trip makes the benchmark targets in
[performance.md](performance.md) unreachable.

## Failure behaviour

Every stage fails closed (ADR-0008). An upload that cannot be encrypted, stored,
extracted, or protected does not proceed, and no partially protected text is
transmitted.

## Related decisions

- ADR-0020 — encrypted object storage
- ADR-0021 — user-scoped document keys
- ADR-0022 — batch vault operations
- ADR-0027 — MinIO as the local object store
- ADR-0008 — fail closed
