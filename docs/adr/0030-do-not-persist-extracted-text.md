# ADR-0030: Do Not Persist Extracted Plaintext

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

[data-classification.md](../data-classification.md) already classes extracted
text as **Restricted**, with storage "prefer none", retention "minimal", and
logging "never". The reasoning is in the same document: extracted text "is
plaintext originals in bulk, minus the file format."

That makes it strictly worse than the stored document it came from. The document
in the bucket is sealed under a per-document key (ADR-0021) and is opaque to
anyone with storage access. Extracted text is the same content with the
encryption and the file format removed — searchable, greppable, and immediately
readable by anything that can see it.

There is a real pull toward caching it. Extraction is the expensive step: a
process spawn plus a parse, per document, every time. Caching the result would
make a second pass over the same document nearly free, and the phase that adds
detection will want to run over a document more than once.

The pull is exactly why this needs to be a decision rather than a default.

## Decision

**Extracted text is never persisted.** It exists only for the duration of the
call that produced it.

Specifically:

- **No database persistence.** No table, no column, no JSON blob. Phase 2 adds
  no migration.
- **No object-store persistence.** Nothing is written to the bucket except the
  sealed original, which Phase 1 already wrote.
- **No temporary files.** Extraction operates on an in-memory buffer and
  `io.BytesIO`; nothing is written to a filesystem, so there is no temporary
  plaintext to delete and no error path on which deletion can be forgotten.
- **No content in logs.** Modules that handle extracted text either do not log
  at all (`extractors.py`, `validation.py`) or log identifiers and counts only
  (`processing.py`).
- **No content in errors.** Failures carry a reason code, never a fragment of
  the file. Reason codes are for the operator reading a log; quoting the
  document back would describe it to whoever supplied it.

The consequence for state is deliberate: because nothing is persisted, there is
nothing for a status to describe, so **Phase 2 adds no `DocumentStatus`
member**. `receiving`, `stored`, and `failed` remain the whole lifecycle. A
status the system cannot reach is a lie told to whoever polls for it.

## Consequences

### Positive

- **Data minimization.** The system holds one copy of a document's content, in
  the form that is encrypted at rest.
- **Reduced breach impact.** A database compromise yields metadata and encrypted
  filenames. Extracted text would have made it yield readable clinical and
  personal content in bulk.
- **No retention problem to solve.** Data that is never written needs no
  expiry job, no deletion audit, and no answer to "where else did this go" in a
  subject access request.
- **No temporary-file class of bug.** The failure mode where a crash leaves
  plaintext in `/tmp` cannot occur, because nothing is written there.
- **The container's read-only filesystem stays viable.** The gateway runs with
  `read_only: true` and a 64 MB tmpfs; an extraction path that wrote temporary
  files would have to justify writable storage.

### Negative

- **Extraction is repeated.** Every pass over a document pays the parse again.
  Measured against the alternative — a durable, searchable, unencrypted copy of
  every uploaded document — this is the cheaper problem.
- **Phase 3 must hold the segments it needs in memory for the life of a
  request**, bounded by `MAX_DOCUMENT_BYTES` and `MAX_EXTRACTED_CHARACTERS`.
- **No resume after a crash.** A failed run starts over rather than continuing
  from cached text.

## Alternatives Considered

- **Cache extracted text encrypted, under the document's own key.** Cheapest
  performance answer, and it doubles the number of ciphertexts holding the same
  content while adding a retention obligation and a second thing to rotate. The
  encryption would be real; the exposure would still grow. Rejected.
- **Cache in Redis with a short TTL.** Puts bulk Restricted content in the store
  whose whole design premise (ADR-0003) is short-lived token mappings, and makes
  a Redis snapshot a document leak. Rejected.
- **Write to a temporary file and delete it.** The conventional approach, and it
  is only as good as the error paths. Rejected in favour of never writing.
- **Persist a redacted or hashed form.** Neither answers a real need in this
  phase, and a "redacted" copy is a copy whose redaction nothing has verified.
  Rejected as speculative.

## Implementation Constraints

- `DocumentProcessor.segment()` returns a `SegmentedDocument` and stores
  nothing. Its only log line carries tenant, document, content type, page count,
  character count, and segment count.
- Modules holding extracted text define a `__repr__` that reports counts, so a
  traceback cannot spill a document.
- If a future phase needs caching, it needs a superseding ADR — not a
  configuration flag.

## As Built (Phase 2)

`app/documents/processing.py`.

`tests/unit/test_document_processing.py::TestRetentionAndLogging` is what keeps
this true as the code grows: it asserts that the object store is unchanged
across an extraction, that no canary reaches the stored bytes, that the document
count in the database is unchanged, that no table named for segments or
extraction exists, and that no canary reaches a log line — including the
filename, which is itself a canary in that test.
