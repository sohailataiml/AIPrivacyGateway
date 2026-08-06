# Secure Document Processing

Extends the prompt pipeline to uploaded files.

**The document pipeline is built end to end.** Storage, extraction,
segmentation, detection, protection, the outbound scan, transmission,
restoration, and the audit attestation all run, and
`POST /v1/documents/{id}/process` reaches them. This document marks what each
stage does and what it still does not, because the most useful thing a design document can tell a reader
is which half of it is true today.

## Pipeline

```text
Upload → Validate → Encrypt and store → Extract → Segment → Detect → Protect
      → Batch vault write → Serialize → Outbound scan → LLM → Restore → Attest
      ──────────────────────────────── all built ────────────────────────────
```

Phase 5 added **one route, one migration, and still no new `DocumentStatus`
member** — nothing about a request outlives it, so there is still nothing for a
status to describe (ADR-0032). The migration adds two nullable audit columns and
touches no document table.

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

## Detection and labeled spans — built

Segmentation hands the detector overlapping windows on purpose, so the same
value is reported more than once and a cut can manufacture a fragment that looks
like a whole entity. Turning that back into one decision per character is the
work of this stage, and the order of the steps is load-bearing (ADR-0031):

1. **Promote** each detection to global offsets via `Segment.to_global`.
2. **Coalesce** detections sharing an `(entity_type, start, end)` identity,
   keeping the **highest** score and the union of the segment indexes. The
   segment that saw the value with its context intact is the one that scored it
   right, and the maximum can only move a span *over* a policy threshold.
3. **Select confident** — drop spans below the policy's `min_score` for their
   type. Dropped, not labeled `ALLOW`: the policy has decided they are not
   detections, so they appear in no count.
4. **Resolve overlaps** with the same severity-first rule the prompt path uses
   (`architecture.md` §9.4). A fragment loses to the whole value it came from
   because the rule already prefers the longer span; no special case exists.
5. **Label** each survivor with the policy's action and the pages it touches.

**Confidence is filtered before overlaps are resolved, and the reverse order
loses values.** A sub-threshold `API_KEY` overlapping an above-threshold
`EMAIL_ADDRESS`: severity is the first key of the ordering rule, so resolving
first lets the api key win the span and then be dropped for confidence, leaving
nothing protecting those characters.

### What the detector is asked

The full supported entity set, never narrowed to the policy's configured types.
Narrowing recreates defect 7 — the policy's protective default for an
unconfigured type cannot fire if no such entity is ever detected. Diagnostics
are off and not configurable: a recognizer name is diagnostic output for a
privileged caller inspecting one prompt, and it never travels with a document's
spans.

### Bounds and refusals

| Control | Setting | Why |
|---|---|---|
| Segments detected at once | `DOCUMENT_DETECTION_CONCURRENCY` (4) | Presidio runs on a worker thread per call; an unbounded fan-out starves the request path. Shared across documents, not per document |
| Labeled spans per document | `MAX_DOCUMENT_ENTITIES` (10,000) | Bounds the vault batch the protection phase will write. Not the policy's `max_entities`, which is sized for a prompt and would refuse an ordinary clinical document |
| A blocked entity type | policy | `PolicyViolationError`. The type is recorded; the value is not |
| A failing segment | — | Cancels the rest. `asyncio.TaskGroup`, not `gather`: a document already refused should not go on paying for detection |

### Readiness (ADR-0032)

The result is an `AnalyzedDocument`, and its **construction is the checkpoint**.
It cannot hold spans that overlap, run backwards, fall outside the buffer, or
carry `BLOCK`. So the phase that protects a document does not re-validate any of
that — holding one means the policy has been applied and a right-to-left splice
over its spans is safe. The same reasoning as `ProtectedChatRequest`, and the
reason there is still no new `DocumentStatus` member: nothing is persisted, so
there is nothing for a status to describe.

Counts are derived from the spans on each call rather than stored, so a summary
cannot disagree with what will actually be protected.

## Protection — built

Applying the labeled spans, and the last stage before a document could be sent
anywhere. `DocumentProtector` **calls the prompt tokenizer** rather than
implementing a second one (ADR-0033), because the two things it would duplicate
are the two where a mistake is silent: the splice runs **right to left** (every
offset indexes the original string) and mappings are minted in **one call**
(ADR-0022 — a round trip per span is arithmetically fatal on a document).

Three things have to line up for that reuse to be safe, and they are most of
the module:

| Concern | Answer |
|---|---|
| Which policy applies | The snapshot `AnalyzedDocument` carries, not a re-resolution. Policy is cached for 30s and editable at any moment; re-resolving could apply actions the labels never agreed to |
| Which entity budget applies | `MAX_DOCUMENT_ENTITIES`, substituted through a read-through view of the snapshot. The tokenizer's own ceiling is the per-*request* one and would refuse documents analysis accepted |
| Which session the tokens belong to | The caller's. A token minted in one session resolves in no other, so a document's tokens must be minted in the session that will quote them |

The tokenizer re-derives actions from the policy it is handed, so the derivation
reproduces the labels — and the protector **checks that it did**, refusing a
result that acted on a different number of spans than were labeled. A silently
dropped span would otherwise mean text with an original still in it and a
summary calling the document protected.

`ProtectedDocument` is the provider checkpoint, the document-shaped counterpart
of `ProtectedChatRequest`. It carries no mappings: the originals are in the
vault, which is where restoration reads them.

A blocked entity type is refused by *analysis*, before protection begins, so a
document destined to fail reaches no vault call and leaves no TTL to wait out.

## Outbound, transmission, and restoration — built

The last four stages, in the order the guarantees require. Moving any of them
breaks something specific, so the order *is* the design:

| Stage | Why it is here and not later |
|---|---|
| Serialize | One canonical byte string per request, produced **once** and used for the scan, the transmission, and the attestation. Three renderings would be three chances to check one thing and send another |
| Outbound scan | Before the provider call. Afterwards the leak has happened, and a check that runs then is a report rather than a control (ADR-0008) |
| Transmit | Only a payload that passed the scan reaches an adapter |
| Restore | After the answer returns, failing closed — half-restored text is indistinguishable from a successful answer with fewer entities |
| Attest | On **every** path that reached serialization, including the blocked one. A row proving the check ran and refused is the evidence the mechanism exists to produce (ADR-0024) |

### The serialization

Framing version, provider alias, model alias, policy version, and each message's
role and content, every field length-prefixed so no regrouping of the same bytes
can collide. Deliberately **not** the provider's wire format: an OpenAI JSON body
belongs to that adapter and would change with its SDK, so attesting it would tie
the audit trail to a vendor.

The request id is deliberately **outside** the frame. Two identical payloads must
attest identically, or the digest cannot be recomputed — and a digest nobody can
recompute proves nothing.

### The scan

Runs the detector over the exact payload and blocks on any detection the policy
would act on. A type the policy *allows* is not a finding: allowing a type means
the payload is permitted to carry it.

**Detections inside a token or a redaction are discarded first.** A token's
26-character identifier is exactly the shape of an account number, so without
that exclusion the scan would flag the substitutions protection had just made,
refuse every document, and be switched off within a day.

### The attestation

`audit_events.outbound_hmac` holds a keyed digest of the transmitted bytes and
`outbound_scan` holds the verdict. A digest, never a payload — ADR-0013 keeps
raw content out of durable storage and ADR-0015 requires the keyed construction.
The column is not called `payload_hmac` because `AuditRecord` screens field names
against a prohibited-substring list that includes `payload`.

### The route

`POST /v1/documents/{id}/process` takes a provider, a model, an instruction, and
an optional session id. It requires **two scopes** — `documents:read` *and*
`chat:invoke` — because processing reads a document and invokes a model, and a
key holding one but not the other must not reach the operation indirectly.

The instruction is sent as a **system** message, kept apart from the document
rather than concatenated with it, and it is **not tokenized**. That is a stated
limit rather than an oversight: an instruction quoting a patient's name reaches
the provider as written, and the outbound scan is what stands behind it.

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

## What Phase 5 does not do

- **No streaming.** A document answer is returned whole (ADR-0012).
- **The instruction is not protected.** It is the caller's own text and is sent
  as written; only the outbound scan stands behind it.
- **`prompt_hmac` is still null**, on this path and on the chat path.
  ADR-0024 asks for it to be populated or removed; documents populate
  `outbound_hmac`, `response_hmac`, and `session_id_hash`, and the prompt digest
  remains outstanding.
- **The chat pipeline is unchanged.** It has no outbound scan and writes no
  attestation. Everything in this section is the document path only.
- **Nothing is persisted about the request** beyond the audit row. No status, no
  answer, no span map.

Two limits worth stating rather than discovering:

- **The document entity budget is a deployment setting, not a policy field.**
  `PolicyDocument.max_entities` is sized for a chat request and applying it to a
  document would refuse ordinary ones. A tenant therefore cannot tighten the
  document budget below the deployment's until the policy schema gains a field
  for it, which is a schema change and needs its own decision.
- **Detection quality is unchanged and unmeasured on documents.** The recognizers
  are the prompt path's, and `docs/threat-model.md` already names detection
  quality as the largest residual risk in the system. Running them over a
  document does not make them better at PHI; it makes the same recall apply to
  far more text.

## Related decisions

- ADR-0020 — encrypted object storage
- ADR-0021 — user-scoped document keys
- ADR-0022 — batch vault operations
- ADR-0027 — MinIO as the local object store
- ADR-0028 — spawned process isolation for extraction
- ADR-0029 — page-range document offsets
- ADR-0030 — do not persist extracted plaintext
- ADR-0031 — merge document detections on global offsets
- ADR-0032 — readiness is a type, not a status
- ADR-0033 — protect documents with the prompt tokenizer
- ADR-0002 — Presidio as the detection engine
- ADR-0014 — policy-driven entity actions
- ADR-0008 — fail closed
