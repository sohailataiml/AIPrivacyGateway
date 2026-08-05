# Secure Document Processing

Extends the prompt pipeline to uploaded files.

**Phase 1 — secure storage — is built.** Everything from `Extract` onward is
still specification. This document marks the boundary explicitly at each step,
because the most useful thing a design document can tell a reader is which half
of it is true today.

## Pipeline

```text
Upload → Validate → Encrypt and store │ Extract → Segment → Detect → Protect
                                      │      → Batch vault write → Outbound scan
        ─────── built ────────────────┤      → LLM → Restore → Audit
                                      └────── specified ───────
```

The stages after `Detect` are the existing prompt pipeline. What document
processing adds is everything before it, plus segmentation.

## Storage — built

S3-compatible object storage, MinIO in the Compose and interview environment
(ADR-0027), reached through the S3 API only so the local store and a deployed
one differ by configuration rather than by code.
PostgreSQL stores metadata only — identifiers, content type, sizes, checksums,
timestamps, status — and never document bytes (ADR-0020).

Encryption uses a per-document data key derived with HKDF-SHA256 and
AES-256-GCM applied **per chunk**, not to the document as a whole. Associated
data includes tenant, user, document, content type, schema version, purpose,
chunk index, and a final-chunk flag, so a stored object cannot be replayed into
another context, reinterpreted under another schema, reordered, duplicated, or
truncated (ADR-0021). The as-built detail lives in those two ADRs.

### API

| Route | Purpose |
|---|---|
| `POST /v1/documents` | Upload one document, sealed and stored |
| `GET /v1/documents/{id}` | Stream the plaintext back to its owner |
| `GET /v1/documents/{id}/status` | Metadata only — touches no key and no object |
| `DELETE /v1/documents/{id}` | Destroy the object and the row |

Routes are versioned under `/v1` like every other route in the gateway. Tenancy
and identity come from the verified API key, never from the request.

### Accepted types

TXT, PDF, and DOCX. A type is believed only when the extension, the declared
MIME type, and the file's own first bytes all agree; DOCX is a ZIP container, so
all three ZIP records are accepted. Plain text has no signature and is therefore
checked *against* the other types' signatures as well as for UTF-8
decodability — a PDF header is valid ASCII, and a decodability-only check waved
`%PDF-1.7` through under a `.txt` name until a test caught it.

Magic bytes are a header check, not a parse. A well-formed header over nonsense
is stored, because deciding whether a PDF really parses means parsing it, and
parsing is extraction.

### Status

`receiving` → `stored`, or `receiving` → `failed`. There is no `extracted` or
`protected` member: a status the system cannot reach is a lie told to whoever
polls for it. Those members arrive with the phase that can reach them.

### What Phase 1 does not do

No extraction, segmentation, detection, tokenization, restoration, or retention
enforcement. A stored document is bytes the gateway can give back to exactly one
principal, and nothing more.

## Extraction — specified

CPU-bound extraction runs in a **bounded** worker pool. Unbounded extraction is
a denial-of-service vector: a handful of large uploads would starve the request
path.

Temporary plaintext files are deleted immediately, including on the error path.
Extracted text is Restricted data — see
[data-classification.md](data-classification.md) — and the default is not to
retain it.

## Offsets and references — specified

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

## Vault interaction — specified

A document produces far more entities than a prompt does. Mapping writes are
batched (ADR-0022); a per-token round trip makes the benchmark targets in
[performance.md](performance.md) unreachable. The batch protocol itself is
built; nothing in the document path calls it yet.

## Failure behaviour — built for storage

Every stage fails closed (ADR-0008). An upload that cannot be encrypted or
stored does not proceed, and no partially protected text is transmitted.

For the storage phase this is a consistency property as much as a refusal
policy. A document is a row in PostgreSQL and an object in a bucket, with no
transaction spanning the two, so the order of operations carries the guarantee:

1. Validate — pure, before any state exists anywhere.
2. Seal the filename and insert a `receiving` row.
3. Stream the body through one pass that counts, hashes, bounds, and sniffs it,
   sealing and uploading as it goes.
4. Only then mark the row `stored`.

A request destined to fail leaves nothing to clean up, and a row never claims
`stored` for an object that is not there. Deletion runs the other way — object
first, then row — because the opposite order can strand bytes in the bucket that
nothing points at, nothing can reach, and nothing can delete.

An interrupted multipart upload is explicitly aborted, including when the
interruption is a client disconnect arriving as task cancellation. Parts left
behind by a missing abort do not appear in an object listing and are billed
until a lifecycle rule finds them.

## Verification

Storage is verified against real MinIO, not only against the in-memory fake. The
fake cannot fail S3's 5 MiB part minimum, cannot sign a request, and never
disagrees with the gateway about what an object key means; the integration suite
asks the server directly whether an upload is still open, and reads object
metadata with an independent client. CI sets `REQUIRE_OBJECT_STORE_TESTS=1` so a
MinIO that failed to start is a red build rather than a green one full of skips.

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d minio minio-init
TEST_OBJECT_STORE_ENDPOINT=http://localhost:9000 \
    pytest tests/integration/test_documents_minio.py -m integration
```

## Related decisions

- ADR-0020 — encrypted object storage
- ADR-0021 — user-scoped document keys
- ADR-0022 — batch vault operations
- ADR-0027 — MinIO as the local object store
- ADR-0008 — fail closed
