# Non-Functional Requirements

What the gateway must be, as opposed to what it must do. Functional behaviour
lives in [architecture.md](architecture.md) and the ADRs; this document states
the properties every feature is measured against, and — just as importantly —
records which of them have actually been demonstrated.

**Ownership.** Numeric latency targets and the benchmark method belong to
[docs/performance.md](docs/performance.md). Runtime alert thresholds belong to
[docs/observability.md](docs/observability.md) §4. This document does not
restate either; it references them, so there is one place to change a number.

**Status labels** used throughout:

| Label | Meaning |
|---|---|
| **Enforced** | A test fails if the property is broken |
| **Implemented** | The code does it; no test would catch a regression |
| **Specified** | Agreed and written down; not yet built |

A requirement with no status label is a requirement nobody has checked.

---

## 1. Security

| # | Requirement | Status | Where |
|---|---|---|---|
| S-1 | Restricted data is encrypted by the application before it leaves the process | **Enforced** | ADR-0004, ADR-0020 |
| S-2 | Decryption is bound to tenant, user, and document; a wrong value yields an authentication failure, never plaintext | **Enforced** | `tests/security/test_document_crypto_isolation.py` |
| S-3 | Every dependency failure fails closed | **Enforced** | ADR-0008 |
| S-4 | Absence and denial are indistinguishable to a caller | **Enforced** | `tests/security/test_document_authorization.py` |
| S-5 | No secret or key appears in a log, metric label, audit record, or error message | **Enforced** | `tests/privacy/test_document_canaries.py` |
| S-6 | All input is validated at the boundary, and rejected rather than repaired | **Enforced** | `tests/unit/test_document_validation_matrix.py` |
| S-7 | Object storage is private; possessing an object key grants nothing | **Enforced** | `deploy/compose/minio-init.sh`, MinIO integration suite |
| S-8 | Production startup refuses placeholder or missing secrets | **Enforced** | `tests/unit/test_contracts.py` |
| S-9 | Keys are rotatable without re-encrypting existing data | **Implemented** | key id travels with each record |
| S-10 | Key rotation is driven by tooling and monitored | **Specified** | no rotation tooling exists |
| S-11 | Parsers for attacker-supplied files run isolated from the gateway | **Enforced** | ADR-0028, `tests/security/test_document_extraction_isolation.py` |
| S-12 | A parser that hangs, exhausts memory, or crashes cannot take the process with it | **Enforced** | one spawned process per document, terminated on timeout |
| S-13 | Archive expansion is bounded before decompression | **Enforced** | DOCX ratio and entry-count guards read the ZIP directory |
| S-14 | Third-party libraries that touch content have their log floor raised | **Enforced** | Presidio, the OpenAI SDK, and now pypdf/docx/lxml |

### Cryptographic requirements

- **AES-256-GCM** for all application-layer encryption. Documents use a chunked
  framing so a large file is never held whole in memory to be authenticated;
  the vault seals short values in one shot.
- **Per-record key derivation.** A ring key encrypts nothing directly. Document
  data keys come from HKDF-SHA256 over the ring key, a per-document salt, and
  the identity triple.
- **Associated data carries the identity.** Tenant, user, document, content
  type, schema version, purpose, chunk index, and final-chunk flag. Each defeats
  a distinct attack; see the table in ADR-0021.
- **Nonces are random per frame** and never reused under a derived key.
- **No unauthenticated encryption anywhere**, and no path that returns
  plaintext when authentication fails.

---

## 2. Privacy

| # | Requirement | Status | Where |
|---|---|---|---|
| P-1 | Original values never reach a provider, a log, or a durable store in the clear | **Enforced** | ADR-0013, privacy suite |
| P-2 | A filename is Restricted and stored encrypted | **Enforced** | `filename_ciphertext` |
| P-3 | Object keys and object metadata disclose nothing about content or owner | **Enforced** | canary suite |
| P-4 | Identical documents from different principals produce different ciphertext | **Enforced** | crypto isolation suite |
| P-5 | Data classification is decided before a new data type is stored | **Implemented** | [docs/data-classification.md](docs/data-classification.md) |
| P-6 | Retention is enforced automatically | **Specified** | documents persist until deleted |
| P-7 | Extracted plaintext is never persisted, anywhere | **Enforced** | ADR-0030, `TestRetentionAndLogging` |
| P-8 | An entity is never hidden by a segment boundary | **Enforced** | overlap + whitespace-aware cuts, property-tested |

---

## 3. Performance

Targets and method: **[docs/performance.md](docs/performance.md)**. That
document owns the numbers; repeating them here would create two sources of
truth that drift.

Document-storage requirements that are structural rather than numeric:

| # | Requirement | Status |
|---|---|---|
| PF-1 | Memory per upload is bounded by the chunk size, not the document size | **Enforced** — `tests/unit/test_document_lifecycle.py` watches the producer/consumer interleaving |
| PF-2 | Uploads and downloads stream; nothing lands on disk | **Enforced** |
| PF-3 | Multipart is used past the part threshold, so a large upload never needs its length up front | **Enforced** — the MinIO suite asserts a multipart ETag |
| PF-4 | Vault writes are batched, never one round trip per token | **Enforced** — ADR-0022 |
| PF-5 | Extraction concurrency is bounded, so a burst cannot start a process per request | **Enforced** — `EXTRACTION_MAX_WORKERS`, sampled during a parallel run |
| PF-6 | Extraction has a wall-clock deadline that actually ends the work | **Enforced** — the worker is terminated, not abandoned |
| PF-7 | Upload throughput, extraction time, and document latency are measured | **Specified** — not measured |

**Extraction does not stream, and that is deliberate.** A PDF cross-reference
table sits at the end of the file and points backwards, so a parser needs random
access to the whole document. The bytes are buffered in `DocumentProcessor`
under `MAX_DOCUMENT_BYTES`, and that buffer is a further reason the parse happens
in another process. Storage itself streams end to end; this is the one stage
that cannot.

**Configured limits.** `MAX_DOCUMENT_BYTES` defaults to 25 MiB;
`DOCUMENT_CHUNK_BYTES` defaults to 5 MiB, which is also S3's minimum part size.
Neither has been tuned against a measurement.

---

## 4. Availability and reliability

| # | Requirement | Status |
|---|---|---|
| A-1 | Liveness never depends on a downstream dependency; readiness always does | **Enforced** — `tests/unit/test_lifespan.py` |
| A-2 | Startup proves every dependency is reachable, or refuses to start | **Enforced** |
| A-3 | Shutdown releases every handle even when one closer raises | **Enforced** |
| A-4 | A failure at any step leaves one consistent state across the database and the object store | **Enforced** — `TestConsistency` |
| A-5 | A row never claims `stored` unless the object exists | **Enforced** |
| A-6 | An interrupted multipart upload is aborted, including on client disconnect | **Enforced** — asserted against a live MinIO by asking the server for open uploads |
| A-7 | Deletes are idempotent | **Enforced** |
| A-8 | Timeouts bound every outbound call | **Enforced** — a silent endpoint fails within the read timeout, not eventually |
| A-9 | An extraction worker is reaped on every exit path, including timeout | **Enforced** — asserted against `multiprocessing.active_children()` |
| A-10 | A file that stored cleanly may still be refused at extraction, without destroying it | **Enforced** — `TestRefusals` |
| A-11 | Behaviour under concurrency is measured | **Specified** — the system has never been load tested |

---

## 5. Observability

Runtime alerting: **[docs/observability.md](docs/observability.md)**.

| # | Requirement | Status |
|---|---|---|
| O-1 | Logs are structured and carry a correlation id | **Implemented** |
| O-2 | No log line, metric label, or error message carries Restricted data | **Enforced** — the canary sweep covers logs, SQL, metrics, responses, and object keys |
| O-3 | Metric label cardinality is bounded; no identifier or filename is ever a label | **Enforced** |
| O-4 | The metrics endpoint is authenticated outside local use | **Enforced** |
| O-5 | Readiness reports each dependency individually without disclosing infrastructure | **Enforced** |

---

## 6. Operability

| # | Requirement | Status |
|---|---|---|
| OP-1 | `docker compose up` produces a working stack from an empty volume, with no manual steps | **Enforced** — bucket creation is a compose service, not a console click (ADR-0027) |
| OP-2 | The stack makes no paid external call by default | **Implemented** — `DEFAULT_PROVIDER=mock` |
| OP-3 | Configuration is environment variables only; no secret is baked into an image | **Enforced** |
| OP-4 | Schema changes ship as reversible migrations | **Enforced** — `tests/integration/test_migrations.py` |
| OP-5 | Dependencies are pinned by a lock file, and a locked install is verified | **Enforced** — `uv sync --locked` in CI |
| OP-6 | The container runs unprivileged, read-only, with no added capabilities | **Implemented** |

---

## 7. Maintainability

| # | Requirement | Status |
|---|---|---|
| M-1 | Every module boundary is a `typing.Protocol`, so an adapter can be replaced without touching its callers | **Implemented** |
| M-2 | Every architectural decision has an ADR, and code is checked against accepted ADRs | **Implemented** |
| M-3 | Static typing is strict and passes with no ignores outside declared third-party gaps | **Enforced** — `mypy --strict` |
| M-4 | Lint and format are enforced, not advisory | **Enforced** |
| M-5 | Test coverage stays at or above 80% | **Enforced** — currently ~95% |
| M-6 | An adapter that talks to infrastructure is tested against that infrastructure, not only against a fake | **Enforced** — CI runs the MinIO suite and fails if it would skip |

**M-6 is the one worth reading twice.** A fake is a dictionary: it cannot fail
S3's 5 MiB part minimum, cannot sign a request, and never disagrees with the
gateway about what an object key means. Four of this project's defects were
visible only from a running container, and a fifth was a storage test file whose
fixture had never successfully executed. The CI job therefore sets
`REQUIRE_OBJECT_STORE_TESTS=1`, which turns a missing MinIO into a red build
rather than a green one with thirty-five silent skips.

---

## 8. Known gaps

Stated plainly, because a requirements document that lists only satisfied
requirements is marketing.

1. **Nothing has been benchmarked.** Every number in
   [docs/performance.md](docs/performance.md) is a target, not a measurement,
   and the alert thresholds derived from them are provisional.
2. **The system has never run under concurrency.** A-11 is unverified.
3. **No retention enforcement.** Documents persist until something deletes them.
4. **No key rotation tooling.** The format supports it; nothing drives it.
5. **`user` means "API key id".** There is no user model, so per-user scoping is
   per-credential scoping. It is a real boundary, but not the one the word
   implies.
6. **Document processing stops at segmentation.** No detection, tokenization,
   vault interaction, or restoration for documents. Nothing calls
   `DocumentProcessor`: it is composed and closed by the composition root and
   invoked by nothing until the phase that adds detection.
7. **Extraction is header-and-structure deep, not semantic.** A PDF with a
   well-formed object graph and meaningless content extracts successfully.
   Deciding whether a document *means* anything is not extraction's job.
8. **A DOCX reports one page.** Pagination is a rendering decision the reader
   makes and is not stored in the file. Page-accurate DOCX references would
   require laying the document out.
9. **No OCR.** A scanned PDF with no text layer is refused with
   `no_extractable_text` rather than being read as images.
10. **The segment overlap is the guarantee, and it is finite.** An entity longer
    than `SEGMENT_OVERLAP_CHARACTERS` can still be split across a boundary and
    seen only as fragments. The default is sized against the longest value a
    recognizer needs whole, which is a judgement, not a measurement.

## Related documents

- [architecture.md](architecture.md) — what the system is
- [implementation.md](implementation.md) — how it was built, phase by phase
- [docs/performance.md](docs/performance.md) — targets and benchmark method
- [docs/observability.md](docs/observability.md) — runtime alerting
- [docs/threat-model.md](docs/threat-model.md) — what this is defending against
- [docs/data-classification.md](docs/data-classification.md) — what may be stored where
- [docs/adr/README.md](docs/adr/README.md) — the decisions behind all of it
