# Secure Document Processing

Extends the prompt pipeline to uploaded files.

**Phase 1 (secure storage) and Phase 2 (extraction and segmentation) are built.**
Everything from `Detect` onward is still specification for documents. This
document marks the boundary explicitly at each step, because the most useful
thing a design document can tell a reader is which half of it is true today.

## Pipeline

```text
Upload → Validate → Encrypt and store → Extract → Segment │ Detect → Protect
                                                          │ → Batch vault write
        ─────────────────── built ─────────────────────── ┤ → Outbound scan
                                                          │ → LLM → Restore
                                                          └── specified ──────
```

The stages after `Detect` are the existing prompt pipeline. What document
processing adds is everything before it, plus segmentation.

**Nothing calls extraction yet.** `DocumentProcessor` is assembled in the
composition root and closed on shutdown, but no route reaches it and no other
module invokes it. It becomes reachable in the phase that adds detection over
documents. Phase 2 added **no routes, no migration, and no new
`DocumentStatus` member**.

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

## Extraction — built

CPU-bound extraction runs in a **bounded** worker pool. Unbounded extraction is
a denial-of-service vector: a handful of large uploads would starve the request
path.

### Isolation (ADR-0028)

Each document is parsed in **its own spawned subprocess**, not a thread. Threads
would bound concurrency and nothing else: a Python thread cannot be killed, a
runaway allocation is charged to the whole interpreter, and a segfault in a C
extension such as `lxml` ends every in-flight request.

| Mechanism | What it contains |
|---|---|
| One process per document | A crash or an OOM kill stops at the worker |
| `asyncio.Semaphore` | Concurrency capped by `EXTRACTION_MAX_WORKERS` |
| `poll(timeout)` then `terminate()`, then `kill()` | A parser that never finishes |
| Reaping on every exit path | No orphan left holding a core |
| `spawn`, never `fork` | The child inherits no key ring, socket, or pool |

Only **bytes and safe reason codes** cross the boundary: the parent sends the
document, the content type, and a character limit; the child returns page
strings or a short reason. Exceptions are never pickled back, because a
traceback holds frames and a frame holds the document.

A `ProcessPoolExecutor` was rejected: its futures cannot be cancelled once
running, so its timeout abandons the work rather than ending it — worse than no
timeout, because it looks like one.

### Supported types and their guards

| Type | Library | Pages | Guards |
|---|---|---|---|
| TXT | stdlib | 1 | Strict UTF-8; no replacement characters |
| PDF | pypdf (BSD-3) | one per page | Encrypted PDFs refused, not unlocked |
| DOCX | python-docx (MIT) | 1 | ZIP expansion-ratio and entry-count limits |

PyMuPDF is faster and AGPL, which this Apache-2.0 project cannot distribute.

- **Strict UTF-8 for text.** Decoding with replacement would corrupt the very
  characters detection is about to run over, and a mangled identifier is one no
  recognizer matches — fail-open dressed as resilience.
- **Encrypted PDFs are refused.** pypdf offers an empty-password unlock; taking
  it would mean silently processing a document whose author restricted it.
- **DOCX is a ZIP, so it is checked before it is decompressed.** Declared
  uncompressed and compressed sizes come from the central directory, which
  expands nothing. An archive over the ratio limit, or with more members than
  any authored document has, is refused for the cost of a directory read.
- **The character ceiling is enforced inside the child, while accumulating.**
  Checking on return would mean the allocation the limit exists to prevent had
  already happened.
- **A DOCX reports one page**, because pagination is a rendering decision the
  reader makes and is not stored in the file. Inventing page breaks would put
  fabricated references into an audit trail.
- **Table cells are extracted**, tab-separated. Forms put names and identifiers
  in tables, and walking only paragraphs would be a detection gap disguised as
  an extraction detail.

### Parser logging

`pypdf`, `docx`, and `lxml` have their logger floors raised to `INFO`, because
pypdf quotes object contents in its structural warnings. This is the third
recurrence of a leak class this project has already met twice — Presidio logging
match context at DEBUG, and the OpenAI SDK logging request bodies. The floor is
applied inside the child as well as the parent, since a spawned interpreter has
none of the parent's logging configuration.

### Retention (ADR-0030)

Extracted text is Restricted data — see
[data-classification.md](data-classification.md) — and **none of it is
persisted**. No table, no object, and no temporary file: extraction works on an
in-memory buffer, so there is no temporary plaintext to delete and no error path
on which deletion can be forgotten. Because nothing is stored, there is nothing
for a status to describe, which is why Phase 2 adds no `DocumentStatus` member.

## Offsets and references — built

Global offsets and page/segment references are preserved through extraction and
segmentation. Two things depend on this:

- **Correct protection.** A detected span must map back to the exact bytes it
  came from. An offset that drifts by one protects the wrong text.
- **Correct restoration.** Restored output must reassemble in the original
  order.

### One buffer, ranges into it (ADR-0029)

An extracted document is **one canonical text buffer**. A page is a
`(number, start, end)` range and owns no text; a segment is likewise a range,
with **global** offsets. Page and segment text are derived by slicing, never
stored, so a copy cannot drift from its offset — the divergence is
unrepresentable rather than merely tested for.

Pages are ordered, non-overlapping, contiguous, and cover the buffer exactly.
A gap or an overlap is refused at construction, so an offset bug surfaces where
the mistake is rather than where the wrong span eventually lands.

`Segment.to_global(offset)` is the single place segment-local arithmetic is
written, and each segment carries the page numbers it spans.

### Segmentation — built

Segmentation exists because documents exceed model context windows and because
detection quality degrades on very long inputs. Segments must not split entities
across boundaries in a way that hides them from the detector — a boundary
falling mid-value is a fail-open condition.

Two mechanisms answer that, and both are needed:

- **Whitespace-aware boundaries.** A boundary is sought backwards from the size
  limit for a paragraph break, then a line break, then a sentence end, then any
  whitespace, within a window of 25% of the segment size. So a cut never lands
  inside `marguerite.okonkwo@example.test` or `451-88-7396`, which contain no
  whitespace. A run with no whitespace at all — an embedded base64 blob — is cut
  at the hard limit, because it still has to be cut somewhere.
- **Overlap.** Whitespace breaks are not sufficient alone, because many entities
  *contain* whitespace: `Marguerite Okonkwo-Vasquez` splits cleanly at a space
  into two fragments, neither of which is a person's name. Consecutive segments
  repeat `SEGMENT_OVERLAP_CHARACTERS` of the previous one, so any entity shorter
  than the overlap appears whole in at least one segment.

Overlap means an entity can be detected twice at two segment offsets. That is
deliberate and it is the safe direction: global offsets let duplicates collapse
on identity later, whereas a missed entity is unrecoverable. **The overlap is
the guarantee** — an entity longer than it can still be split, which is why the
setting is a privacy control rather than a throughput knob.

A document that extracts to zero characters — a scanned PDF with no text layer —
is refused with `no_extractable_text` rather than yielding zero segments, which
would look like success and send an empty prompt onward.

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

## What Phase 2 does not do

No detection, tokenization, vault interaction, provider call, restoration, or
audit for documents. No route reaches extraction, no `DocumentStatus` member was
added, and no migration was written. `DocumentProcessor` is composed and closed
by the composition root and is invoked by nothing.

## Related decisions

- ADR-0020 — encrypted object storage
- ADR-0021 — user-scoped document keys
- ADR-0022 — batch vault operations
- ADR-0027 — MinIO as the local object store
- ADR-0028 — spawned process isolation for extraction
- ADR-0029 — page-range document offsets
- ADR-0030 — do not persist extracted plaintext
- ADR-0008 — fail closed
