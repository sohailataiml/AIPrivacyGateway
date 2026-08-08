# Build Progress

Status of the Secure AI Gateway against the phase plan in
[implementation.md](implementation.md).

**As of 2026-08-06** — 123 modules under `app/` · **1,672 tests passing, none
skipped** (1,447 unit · 91 privacy · 85 security · 49 integration) · **96%
coverage** (target 90%) · `mypy --strict` clean · ruff clean.

That count is the whole tree in **one session** against live PostgreSQL, Redis,
and MinIO. Run suite by suite it is 48 tests smaller and every one of those is a
silent skip — which is how defects 17 and 18 stayed invisible.

Fourteen ADRs (0020–0033) and eight supporting documents are in the repository.
Eight have shipped: **ADR-0022, batch vault operations** (§8),
**ADR-0020/0021, encrypted document storage** (Phase 15),
**ADR-0028/0029/0030, document extraction and segmentation** (Phase 16),
**ADR-0031/0032, document detection and labeled spans** (Phase 16b),
**ADR-0033, document protection** (Phase 16c), and **ADR-0024, outbound payload
attestation** (Phases 16d–16e — now on **both** routes).

Eleven routes are live: `/v1/chat`, `/v1/detect`, `/v1/sessions/{session_id}`,
`/v1/documents` (POST), `/v1/documents/{id}` (GET, DELETE),
`/v1/documents/{id}/status`, `/v1/documents/{id}/process`, `/health/live`,
`/health/ready`, `/metrics`.

**The stack has been run twice.** The first run — `docker compose up --build`
from an empty volume, migrations, seed, real requests, Prometheus scraping —
produced four defects the suite could not see (§3, defects 8–11). The second
pushed a document with canary PII through the whole storage path against real
MinIO and PostgreSQL, and produced a fifth that made uploads impossible from a
fresh stack (defect 12).

**Every integration suite now runs against real infrastructure**, not only
against fakes: PostgreSQL for migrations, Redis for the batch vault, MinIO for
the object store. CI sets `REQUIRE_OBJECT_STORE_TESTS=1`, so a MinIO that fails
to start is a red build rather than a green one full of skips.

The per-phase checkboxes in `implementation.md` are kept in sync with this file.
Where the two disagree, trust the test suite.

---

## 1. Phase status

| Phase | Name | Tasks | State |
| --- | --- | --- | --- |
| 0 | Repository bootstrap | 12/12 | ✅ Complete |
| 1 | Configuration and lifecycle | 11/11 | ✅ Complete |
| 2 | PostgreSQL, migrations, repositories | 7/7 | ✅ Complete |
| 3 | Authentication, scopes, rate limiting | 10/10 | ✅ Complete |
| 4 | Policy engine | 9/9 | ✅ Complete |
| 5 | Detection engine | 14/14 | ✅ Complete |
| 6 | Tokenization | 10/10 | ✅ Complete |
| 7 | Encrypted Redis vault | 12/12 | ✅ Complete |
| 8 | Secure pipeline orchestration | 10/10 | ✅ Complete |
| 9 | Provider abstraction and OpenAI adapter | 11/11 | ✅ Complete |
| 10 | Output parsing and restoration | 10/10 | ✅ Complete |
| 11 | API endpoints | 6/6 | ✅ Complete |
| 12 | Audit logging | 6/8 | ⚠️ Correlation HMACs unpopulated; retention docs missing |
| 13 | Observability | 5/7 | ⚠️ No OTel, no Grafana JSON |
| 14 | Docker Compose and local ops | 11/11 | ✅ Executed end to end |
| 15 | Secure document storage | 13/15 | ✅ Storage complete; no retention or rotation tooling |
| 16 | Document extraction and segmentation | 11/11 | ✅ Complete; reached only through 16b |
| 16b | Document detection and labeled spans | 9/9 | ✅ Complete; reached only through 16c |
| 16c | Document protection | 7/7 | ✅ Complete; reached through 16d |
| 16d | Outbound attestation and the document route | 7/7 | ✅ Complete; the document path now runs end to end |
| 16e | Shared outbound boundary and instruction protection | 6/6 | ✅ Complete; ADR-0024 satisfied on both routes |
| 16f | Secure chat workspace (frontend) | 4/12 | ⚠️ Chat, document upload, and Privacy Inspector build and run; **no frontend tests at all** |
| 17 | Test strategy | mixed | ⚠️ See §4 |
| 18 | Performance tests | 0/6 | ❌ Not started |
| 24 | Manual security verification | 0/16 | ❌ Not started |

**18 of 21 backend phases are done.** A caller can now upload a clinical
document, ask a model about it, and get an answer with the originals restored —
while the provider sees only tokens and the audit table holds a keyed
attestation of the exact bytes that were sent. What remains is measurement:
nothing has been benchmarked and the system has never run under concurrency.

---

## 2. What exists, by module

| Module | Tests | Notes |
| --- | --- | --- |
| `app/auth/` | 83 | Bearer parsing, scope dependencies, sliding-window rate limit, bounded `last_used_at`, metrics |
| `app/vault/` | 78 | AES-256-GCM envelope, key ring with rotation, AAD binding, atomic get-or-create, TTL on every key |
| `app/detection/` | 72 | Presidio + 5 custom recognizers, allowlist, thresholds, deterministic overlap resolution |
| `app/tokenization/` | 54 | Token grammar + strict parser, random ids, normalization, HMAC fingerprint, all five actions |
| `app/pipeline/` | 51 | Full stage order, ordering guarantees, timeout, bounded concurrency, fail-closed everywhere |
| `app/audit/` | 46 + 8 seam | Privacy-safe record with import-time field enforcement, bounded queue, correlation HMAC |
| `app/policy/` | 43 | Schema, default policy, snapshot resolution, allowlists, TTL cache, validation CLI |
| `app/repositories/`, `app/db/` | 25 + 7 integration | Async SQLAlchemy, Alembic, five tables, tenant-scoped repositories |
| `app/restoration/` | 25 | Batch resolve, unknown-token policy, single-pass substitution |
| `app/domain/`, `app/config/` | 25 | Error catalog, domain contracts, settings with production hardening |
| `app/api/`, `app/observability/` | 17 + 31 routers + 57 observability | Request id, error envelope, body-size limit, allowlist logging, composition root, four v1 routes, `/metrics` |
| `app/llm/` | 17 | Registry, OpenAI adapter (Responses API, `store=False`), retries, mock provider |
| `app/documents/` | 238 + 35 integration | Chunked AES-256-GCM with per-document HKDF keys, boundary validation, streaming multipart upload to S3-compatible storage, tenant- and user-scoped metadata, encrypted filenames |
| `app/documents/extraction/`, `segmentation.py`, `processing.py` | 141 | TXT/PDF/DOCX extraction in a spawned, bounded, killable subprocess; zip-bomb and encrypted-PDF guards; one text buffer with page-range offsets; whitespace-aware segmentation with overlap; nothing persisted |
| `app/documents/analysis/` | 154 | Bounded per-segment detection, global offset promotion, identity coalescing, confidence-then-overlap resolution, policy actions, and a checkpoint type that cannot hold an overlapping or blocked span. 100% covered |
| `app/outbound/` | 46 | The one door to a provider. Canonical serialization, the pre-transmission scan that discards its own tokens *and* scans message by message, the keyed attestation, and the injectable invoker that lets the chat path keep its deadline without getting a second copy of the check |
| `app/documents/pipeline.py` | 16 | Document stage order, refusals, and the audit row |
| `app/documents/protection.py` | 27 | The labeled spans applied through the *prompt* tokenizer — one splice and one batched mint in the system, not two — plus the policy, budget, and session substitutions that make the reuse safe, and a guard that refuses a result acting on a different span count |
| `tests/privacy/` | 52 | Canary regression suite, default-policy thresholds, and the document canary sweep over logs, SQL, metrics, responses, and object keys |
| `tests/security/` | 58 | Document cryptographic isolation matrix (one test per AAD field) and authorization isolation at both the query and ciphertext layers |

---

## 3. Defects found and fixed

Every one of these was found during integration or by running the code. None
were visible from inside the module that contained them.

| # | Defect | Why it mattered |
| --- | --- | --- |
| 1 | **The pipeline could not call the audit service at all.** Pipeline called `record(**fields)`; `AuditService` only has `submit(AuditRecord)`. | `AttributeError` on every request. With `AUDIT_FAIL_CLOSED=true` that is a total outage, not a lost log line. Fixed with `PipelineAuditAdapter` plus a Protocol-conformance test. |
| 2 | **The default policy leaked phone numbers.** `PHONE_NUMBER.min_score` was 0.65; Presidio scores US phone numbers at 0.40 unless the literal word "phone" is nearby. | Ordinary phrasings like `Call 415-555-0142` were discarded by the policy and sent to the provider in the clear. Threshold lowered to 0.40. |
| 3 | **`presidio-analyzer` logs analyzed text at DEBUG** (`Context list is: <value>`). | `LOG_LEVEL=DEBUG` in production would write plaintext PII to stdout. Silenced; verified by mutation. |
| 4 | **The OpenAI SDK logs full request bodies at DEBUG.** | Same class of leak, different library. Silenced; verified by mutation. |
| 5 | **Presidio auto-downloads a missing spaCy model** inside `SpacyNlpEngine`. | A live network call mid-request, and a silent download would mask a broken deployment. Now raises `DetectorUnavailableError`. |
| 6 | **The vault minted timestamped ULIDs.** | A ULID's 48-bit time prefix makes ids sort together and leaks issue time, against Phase 6's "not sequential or guessable". Collapsed onto the canonical random-id grammar. |
| 7 | **Two fail-safes cancelled out.** Policy defaults unknown entity types to `TOKENIZE`, but the pipeline restricted detection to policy-listed types. | Unlisted PII was never detected, so the protective default could never fire. Detection is no longer narrowed. |
| 8 | **Email detection failed open on every private TLD.** Presidio validates each match with `tldextract` against the Public Suffix List and silently discards anything absent from it. | `@acme.internal`, `@acme.lan`, `@acme.corp` and the RFC 2606 names produced *no detection at all* — the address reached the provider in clear text — while `@example.com` scored 1.0. `.internal` is ICANN's reserved private-network TLD, so this is exactly the internal mail an enterprise deployment would leak. Fixed with `InternalEmailRecognizer`, which matches on structure and consults no TLD list of its own. |
| 9 | **The runtime image shipped without the spaCy model.** The final `uv sync` is declarative and prunes anything absent from the lock file, deleting the model an earlier layer had installed. | The image built and started, then failed *every* request closed with `DetectorUnavailableError`. Fixed with `--inexact`. Invisible to the test suite; only running the container found it. |
| 10 | **The container could not start at all.** The venv was built at `/build/.venv` and copied to `/app/.venv`, leaving every console script's shebang pointing at an interpreter the runtime image does not have. | `exec /app/.venv/bin/uvicorn: no such file or directory` — an error that names the script rather than the interpreter actually missing. The same mismatch also broke `spacy download`, because uv resolves its environment from the working directory. The builder now works in `/app`. |
| 11 | **The Dockerfile ran two uvicorn workers.** | Four bounds are documented as per-process: the provider concurrency semaphore, the audit queue and its depth gauge, the `last_used_at` write bound, and the Prometheus registry. Two workers silently doubled three of them and split the fourth, so every metric rate was understated by whatever share of scrapes the other worker answered. Now one worker; scale with containers. |
| 12 | **`docker-compose.yml` shipped a 34-byte document key.** `DOCUMENT_KEY_LOCAL1` decoded to `local-compose-document-key-32bytes` — the label says 32, the string is 34. | AES-256 needs exactly 32, so **every document upload against the composed stack failed with a 503**, and the storage phase was unusable from a fresh `docker compose up`. Nothing in the suite read that file. `tests/unit/test_contracts.py::TestShippedKeyMaterial` now decodes every ring key in `docker-compose.yml` and `.env.example` and asserts 32 bytes, and checks that each `*_ACTIVE_KEY_ID` names a key that exists. |
| 13 | **A wrong-length key was reported as a missing one.** `DocumentCipher._derive` caught every exception from the key ring and flattened it to `reason=unknown_key_id`. | The ring already distinguishes `unknown_key_id` from `key_length_invalid`, and the flattening discarded exactly the information needed. Diagnosing defect 12 meant reading the log, concluding the key was absent, and finding it present — the reason code sent the investigation the wrong way. The ring's own reason now passes through. |
| 14 | **The MinIO integration suite had never executed.** Its `store` fixture assigned `built.put = tracking_put` to record keys for cleanup; `S3CompatibleDocumentStore` defines `__slots__`, so every test in the file errored at setup. | The file read as thorough and verified nothing, which is worse than having no file: it made the storage adapter *look* covered. Coverage told the same story — `s3.py` sat at 34%. Rewritten to record keys where they are minted, and now at 93%. |
| 15 | **Filename validation accepted bidirectional override characters.** `normalize_filename` rejected the `Cc` category and nothing else; `U+202E` and its relatives are `Cf`. | `report‮txt.pdf` renders as `report.fdp.txt`, so what a reviewer approves and what is stored are two different names. Rejected individually rather than by refusing all of `Cf`, because that category also holds the zero-width joiner and non-joiner, which are ordinary in Persian, Indic scripts, and emoji sequences. |
| 16 | **The canary sweep was reading an empty log.** `configure_logging` calls `logging.basicConfig(..., force=True)` during lifespan startup, which removes every root handler — including pytest's `caplog`. | Every "no PII in logs" assertion in the new privacy suite passed against an empty string. Found only because the SQL sweep asserted it had found statements to search. The handler is now re-attached after startup, and each sweep asserts it found something before asserting it found nothing bad. |
| 17 | **Running a migration disabled every application logger, permanently.** `migrations/env.py` calls `logging.config.fileConfig(alembic.ini)`, whose `disable_existing_loggers` argument defaults to `True`. Every logger not named in `alembic.ini` — that is, every `app.*` logger — gets `disabled = True`, and nothing ever re-enables it. | `tests/unit/test_vault.py::test_no_plaintext_mapping_appears_in_logs_when_encryption_fails` passed when its file ran alone and failed once the whole tree ran in one session, because by then the migration suite had run. **Worse than the failure is what it implies for the tests that pass:** every other "no sensitive value appears in the logs" assertion after that point was reading an empty list and passing for the wrong reason — defect 16 again, arriving from a different direction. Fixed at the source with `disable_existing_loggers=False`, which is also correct for any process that runs a migration alongside application code. Alembic ships this default in its generated template. |
| 18 | **Starting the application permanently changed log filtering for the rest of the session.** [^17] `configure_logging` calls `structlog.configure` with `BoundLoggerFilteringAtInfo` and `cache_logger_on_first_use=True`, so every module logger caches a wrapper that drops `DEBUG` before it reaches the standard library. | Not the cause of defect 17, but the same hazard one layer up, and it makes every `caplog.set_level(DEBUG)` assertion vacuous once any test has started an app. Found while investigating 17. `tests/conftest.py` now snapshots and restores the logging configuration around every test, and clears the cached loggers so the restore actually takes effect. |

[^17]: Restoring the configuration was not enough on its own.
`cache_logger_on_first_use=True` means each module-level logger caches its bound
form on first call and keeps it through any later reconfiguration, so
`tests/conftest.py` also clears that cache — the cached `bind` only. Deleting
`_logger` alongside it, as the first attempt did, sends structlog's proxy into
infinite recursion on the next log call.
| 19 | **A segment could be wholly contained in the one before it.** When the only break in the search window fell inside the previous segment, `_end_of_segment` returned an end that had already been covered. | No new characters, so no progress in the sense that matters. Coverage and ordering still held, which is why every hand-written example passed; on adversarial input — a break every few characters with an overlap near the segment size — it degenerates into a near-identical segment per character, and detection work multiplies with it. Found by Hypothesis at `text='0000000 00', max_characters=8, overlap=7`, on a run that explored examples an earlier run had not. The boundary search now rejects a candidate at or before the previous end and falls back to the hard limit, which is provably past it. |
| 20 | **Every document log line silently lost its fields.** `drop_unlisted_keys` is deny-by-default, and `document_id`, `content_type`, `byte_size`, `page_count`, `character_count`, `segment_count` were never added to `ALLOWED_EVENT_KEYS`. | `document_stored`, `document_segmented`, and every document error carried a bare event name and a tenant id — nothing that could tie a failure to a document. The allowlist reports a dropped key by name in `_dropped_keys`, so the evidence was in every log line the whole time, in a field nobody read. **Deny-by-default is why this was an observability bug and not a leak**, and also why it survived two phases: it fails safe, silently, and by design. Found while writing the Phase 16b log line, which would have been the third one to lose its fields. Fixed by allowlisting the document keys — Internal, every one, and the filename deliberately still absent — with `test_no_document_log_line_loses_fields_to_the_allowlist` asserting no `_dropped_keys` marker survives a full upload-and-analyze. |

### Lessons worth keeping

- **Nothing tested the seams.** Defects 1 and 6 existed because each module was
  correct alone. The fix is a conformance test at every Protocol boundary.
- **Nothing tested real component pairs.** Defect 2 survived 776 passing tests
  because unit tests define their own policies and detector tests ignore policy.
  `tests/privacy/test_default_policy_thresholds.py` now pairs the real detector
  with the real default policy.
- **Third-party debug logging is a recurring leak class.** Defects 3 and 4 are
  the same bug in two libraries. Any new dependency that touches message content
  needs its logger floor raised.
- **Set thresholds by what a mistake costs, not by detector confidence.**
  Tokenization is reversible, so a false positive is nearly free — the caller
  still gets the original value back. A miss leaks permanently.
- **A privacy control must not depend on an allowlist someone curated.**
  Defect 8 is defect 2 in a different costume: a dependency deciding, on data
  the authors never reviewed, that a real identifier was not one. Presidio's
  TLD list is reasonable for validation and wrong for a fail-closed control.
  Prefer matching on structure and letting policy decide.
- **Five of sixteen defects were only visible from a running container.**
  Defects 8–11 and 12 all passed a green suite, `mypy --strict`, and ruff.
  Three of them (9, 10, 12) meant the service could not perform its function at
  all. A green suite says the code is consistent with itself, not that the
  artifact you ship works.
- **A file the test suite never reads is a file with no tests.** Defect 12 lived
  in `docker-compose.yml`, which every deployment path uses and no test opened.
  Shipped configuration is code; base64 that is *nearly* the right length is the
  perfect defect, because it looks correct, parses cleanly, and fails only at
  the moment of use.
- **A test that has never run is worse than a missing test.** Defect 14 is the
  clearest case: an integration file full of careful assertions, none of which
  had ever executed, sitting next to a coverage number that said so plainly if
  anyone had looked. The habit that catches this is asserting non-vacuity —
  defect 16 was found *only* because a sweep checked it had something to search
  before checking that nothing bad was in it.
- **Run the whole tree in one session, not suite by suite.** Defects 17 and 18
  are invisible to `pytest tests/unit` followed by `pytest tests/integration`:
  each passes, and the contamination only shows when one session contains both.
  The per-suite commands in the Makefile are convenient and are not the gate;
  `make test-all` and the final CI step are.
- **A passing privacy assertion is worth checking for a pulse.** Defect 17's
  visible symptom was one failing test. Its real cost was every *other* "nothing
  sensitive in the logs" test that ran after it and passed against an empty
  list. An assertion that something is absent should first assert that it was
  looking at something.
- **Beware library defaults that reach outside their own scope.**
  `logging.config.fileConfig` disables every logger it does not know about, and
  Alembic's generated `env.py` ships that default. It is a reasonable default
  for a standalone CLI and wrong for anything running in a live process — and
  nothing warns you, because a disabled logger fails silently by definition.
- **Deny-by-default fails safe and silently, which is two different things.**
  Defect 20 sat through two phases because the logging allowlist did exactly
  what it was designed to do: drop what it did not recognise, without
  complaining. Nothing broke, no value leaked, and every document log line was
  empty of anything an operator could use. A control that silently discards
  correct input needs a test that the input arrives, not only a test that bad
  input does not.
- **Property-based tests earn their keep on the second run, not the first.**
  Defect 19 passed a full green suite and then failed the next time Hypothesis
  explored a different corner. The properties worth generating are the ones
  whose failure mode is "still correct, just quietly much worse" — no exception,
  no wrong answer, and no hand-written example that happens to hit it.
- **A diagnostic that discards information costs more than it saves.**
  Defect 13 turned a five-minute fix into a longer one by reporting a present
  key as absent. Error codes are for the person holding the pager; collapsing
  distinct failures into one code to look tidy trades their time for nothing.
- **A test that encodes a known gap should assert both directions.** The canary
  suite documented "the real detector cannot see this" — correct when written,
  and it failed loudly the moment the detector improved, which is what a good
  test does. It now records coverage in `REAL_DETECTOR_COVERS` and asserts both
  halves, so a regression that reopens the leak cannot pass quietly.

---

## 4. Known gaps and caveats

Read these before trusting a checkmark.

- **All three integration suites now run against real infrastructure.**
  Migrations against PostgreSQL (`0001 → 0002`, both directions), the batch
  vault against Redis, and the object store against MinIO — 49 tests, none
  skipped. They are wired into CI, and the object store suite fails rather than
  skips when `REQUIRE_OBJECT_STORE_TESTS=1`.
- **The stack has been run, but not exercised under load.** Two cold starts,
  migrations, seed, and hand-driven requests including a full document
  round-trip — enough to prove the path works, not enough to characterise it.
  Nothing here has seen concurrency.
- **`test_outbound_payload_carries_tokens_and_no_originals` was
  timing-sensitive** and now uses generous timeouts, because the OpenAI SDK
  resolves platform details in a worker thread on its first request and that
  landed outside a 4.5-second budget under `pytest --cov`. The proper fix is
  still to make the adapter's deadline injectable rather than to widen it per
  test. The same instrumentation slowness overran `asgi_lifespan`'s 5-second
  startup default, so the API suites now pass an explicit 60-second bound.
- **Integration coverage beyond storage is thin.** The plan calls for full-flow,
  TTL expiry, concurrent token creation, session deletion, and dependency-outage
  integration tests for the chat path; only the vault batch write is covered.
- **`tests/security/` now exists** and holds the document cryptographic
  isolation and authorization matrices. Security assertions for the chat path
  are still spread through module tests rather than collected there.
- **Document storage has no retention enforcement and no key rotation
  tooling.** Documents persist until deleted. The wire format carries a key id
  per object so rotation is possible without re-encrypting, but nothing drives
  it. Both are listed as gaps in [NFR.md](NFR.md) §8.
- **`user` means "API key id".** There is no user model, so per-user document
  scoping is per-credential scoping. It is a real boundary — two keys in one
  tenant cannot read each other's documents — but not the one the word implies.
- **Documents stop at detection.** No tokenization, vault interaction, provider
  call, or restoration for documents. `DocumentStatus` still has no member the
  system cannot reach; ADR-0032 records why readiness is a type rather than a
  status, and Phase 16b added no migration.
- **`DocumentAnalyzer` is composed but never invoked.** The composition root
  builds it; no route reaches it and no other module calls it. It becomes
  reachable in the phase that protects a document. Its coverage therefore comes
  entirely from its own suites.
- **Detection quality over documents is unmeasured.** The recognizers are the
  prompt path's, and `docs/threat-model.md` already names detection quality as
  the largest residual risk in the system. Running them over a document applies
  the same recall to far more text; nothing has been evaluated against a
  labelled corpus.
- **A tenant cannot tighten the document entity budget.** `MAX_DOCUMENT_ENTITIES`
  is a deployment setting, because `PolicyDocument.max_entities` is sized for a
  chat request and applying it to a document would refuse ordinary ones. Adding
  a per-tenant field is a policy schema change.
- **Extraction does not stream.** A PDF cross-reference table sits at the end of
  the file and points backwards, so the parser needs the whole document. The
  bytes are buffered under `MAX_DOCUMENT_BYTES`, which is one more reason the
  parse happens in another process.
- **A DOCX reports one page and there is no OCR.** Pagination is a rendering
  decision that Word does not store, and a scanned PDF with no text layer is
  refused rather than read as images.
- **The segment overlap is a finite guarantee.** An entity longer than
  `SEGMENT_OVERLAP_CHARACTERS` can still be split across a boundary. The default
  is a judgement about the longest value a recognizer needs whole, not a
  measurement.
- **The privacy regression suite hand-rolls restoration**, because
  `app/restoration/` did not exist when it was written. It should be rewired to
  the real module.
- **Tracing is not implemented.** `OTEL_EXPORTER_OTLP_ENDPOINT` sits in
  `Settings` and nothing reads it. It was optional in the plan; the setting
  existing without an implementation is the misleading part, and it is called
  out in `docs/observability.md` §5 for that reason.
- **The outbound scan is per message, not over the concatenation.** Presidio's
  NER is context-sensitive, and scanning the join reports entities that exist
  only at the seam — `"An unremarkable week, clinically."` yields nothing alone
  and `DATE_TIME` at 0.85 once a sentence precedes it. Per-message scanning
  matches how protection ran. An entity genuinely spanning two messages goes
  unreported; the claim that no real value does is a judgement, not a proof.
- **The frontend has no automated tests.** `frontend/` builds, typechecks, and
  lints clean, and the workspace has been exercised by hand — but there is no
  component test, no Playwright flow, and no CI job for it. Every backend claim
  in this file is backed by a suite; nothing in the UI is. Treat it as
  demonstrated, not verified.
- **Only the workspace exists.** `architecture.md` §22.7–22.12 specify a
  dashboard, session explorer, audit explorer, policy manager, and provider
  pages. None are built, and most need read APIs the backend does not expose.
- **Instruction protection costs a second vault batch.** The document and the
  instruction are two `transform` calls under one session. ADR-0022 forbids a
  round trip per *token*, not per message, so this is inside the rule — but it
  is two round trips where one would do.
- **Two metrics deviate from the architecture's label specification.** `model`
  is not a provider label and `entity_type` is not a vault label, because at
  the point of recording both strings are caller-supplied and neither module
  can bound them. Reasoning in `docs/observability.md` §1.
- **The alert thresholds in `docs/observability.md` are unmeasured.** They are
  reasoned starting points, not values derived from this system's behaviour
  under load — there has been no load.

---

## 5. How to verify any of this

```bash
# See the privacy transformation actually happen
PYTHONPATH=. ./.venv/Scripts/python.exe scripts/demo_pipeline.py

# Full suite
./.venv/Scripts/python.exe -m pytest tests -q

# Both routes end to end, against a provider that records what it saw
make test-e2e   # or: python tasks.py test-e2e

# The canary suite specifically
./.venv/Scripts/python.exe -m pytest tests/privacy -m privacy -v

# Detection over documents: the span algebra, the analyzer, and the sweep
./.venv/Scripts/python.exe -m pytest   tests/unit/test_document_analysis.py   tests/unit/test_document_analysis_spans.py   tests/privacy/test_document_analysis_canaries.py   tests/security/test_document_analysis_isolation.py -q

# Coverage against the 90% target
./.venv/Scripts/python.exe -m pytest tests --cov=app --cov-report=term

# Types and lint
./.venv/Scripts/python.exe -m mypy app
./.venv/Scripts/python.exe -m ruff check app tests scripts

# What routes actually exist (currently: ten)
./.venv/Scripts/python.exe -c "from app.main import create_app; print(sorted(create_app().openapi()['paths']))"

# The three integration suites, each against real infrastructure. None may skip.
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres redis minio minio-init
TEST_DATABASE_URL=postgresql+asyncpg://gateway:gateway@localhost:5432/gateway_test \
TEST_REDIS_URL=redis://localhost:6379/15 \
TEST_OBJECT_STORE_ENDPOINT=http://localhost:9000 \
REQUIRE_OBJECT_STORE_TESTS=1 \
  ./.venv/Scripts/python.exe -m pytest tests/integration -m integration -q

# What a scrape returns, and that it carries nothing identifying
./.venv/Scripts/python.exe -m pytest tests/unit/test_observability.py -q
./.venv/Scripts/python.exe -m pytest tests -m security -v
```

Run the whole stack, in this order — the migrate and seed steps run *inside*
the stack because the compose database publishes no host port:

```bash
make compose-up        # or: python tasks.py compose-up
make compose-migrate   # alembic upgrade head, in the gateway container
make compose-seed      # prints an API key exactly once -- copy it
curl localhost:8000/health/ready

curl -X POST localhost:8000/v1/chat \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"provider":"mock","model":"general-chat",
       "messages":[{"role":"user","content":"Email jane@acme.internal"}]}'

# Metrics require the scrape token; Prometheus is at :9090.
curl -H "Authorization: Bearer $METRICS_TOKEN" localhost:8000/metrics

# Store a document, read it back, and confirm the bucket holds no plaintext.
curl -X POST localhost:8000/v1/documents \
  -H "Authorization: Bearer $KEY" \
  -F "file=@report.pdf;type=application/pdf"
curl localhost:8000/v1/documents/$ID -H "Authorization: Bearer $KEY" -o out.pdf

docker compose exec minio mc alias set l http://127.0.0.1:9000 \
  sgw-local-access-key sgw-local-secret-key-not-for-production
docker compose exec minio mc ls --recursive l/sgw-documents   # opaque keys only
docker compose exec minio mc cat l/sgw-documents/<key> | strings | head
```

`make <target>` also works where GNU make is available; `python tasks.py
<target>` runs the identical commands on Windows.

---

## 5b. Deployed to Render — unfinished, read this first

Live at **https://sgw-workspace.onrender.com/chat** and
**https://sgw-api.onrender.com**. Created via the Render API, not the
dashboard, so `render.yaml` and the running services can drift — treat the
services as the truth and fold changes back into the file.

| Resource | Id | State |
|---|---|---|
| Workspace | `srv-d9qg5ps9v7es73eu0cm0` | ✅ serving |
| API | `srv-d9qg5p6gekts7395t9cg` | ✅ live, **not ready** |
| Postgres | `dpg-d9qfuhvavr4c73fgktu0-a` | ✅ up, **no schema** |
| Key Value | `red-d9qg2v2jobas7381ju2g` | ✅ up |
| Object store | `srv-d9qg539t0dsc7380lkeg` | ❌ down |

### Two things block a working demo

**1. The object store is down.** `/health/ready` reports
`object_store: down`. Two causes, one fixed in `render.yaml` and neither yet
live:

* Render routes a private service on **port 10000**; MinIO defaults to 9000.
  The running container is still on 9000 because every failed update rolls
  back to the last working config.
* The `sh -c "…"` wrapper that pre-creates the bucket is mangled by Render's
  command parsing — it fails with
  `sh: line 1: <entire string>: No such file or directory`.

Untangle them rather than fixing both at once: set `dockerCommand` to plain
`minio server /data --address :10000` (no shell, nothing to misquote), then
create the bucket from Render's dashboard shell:

```bash
mc alias set l http://127.0.0.1:10000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD
mc mb l/sgw-documents
```

**2. Migrations have never run.** `alembic upgrade head` against the Render
Postgres, before first use. Skipping it reproduces the local failure exactly:
the first audit write fails on missing `outbound_hmac`/`outbound_scan`
columns, `AuditService` latches into `degraded`, and every request afterwards
returns `AUDIT_UNAVAILABLE` until the service restarts. Fixing the schema is
not enough on its own — the latch needs a restart.

**Order matters and is easy to get wrong:** rebuild → migrate → restart →
smoke test. Getting it wrong is what produced the latch locally.

### Also outstanding

* **`deploy.secrets.txt`** in the repo root holds the production secrets.
  Gitignored, generated in-process, never printed to a terminal. Store them
  somewhere safe and delete the file.
* **The demo needs an API key to be usable.** A hiring partner opening the URL
  hits the paste-a-key gate. The fix is a **server-side proxy** in the
  workspace — a route handler that attaches a demo key from a plain
  `GATEWAY_DEMO_API_KEY` (never `NEXT_PUBLIC_*`, which bakes it into the
  client bundle). That keeps ADR-0019 intact and makes CORS irrelevant, since
  everything becomes same-origin.
* **No frontend tests, still.** Four defects reached a user in one session —
  the CSP blocking hydration, a stale image, an error parser that disguised
  the failure, and the migration ordering. All four passed `build`, `lint`,
  `typecheck`, and 1,672 green backend tests, because none of those execute a
  page or check which commit an image was built from.

---

## 6. Next steps, in order

0. **Run the batch-vault integration tests against real Redis.** Everything in
   §7 passes on a Lua emulator. `TEST_REDIS_URL=redis://localhost:6379/15
   pytest tests/integration/test_vault_redis.py -m integration`.
1. **Work the §24 manual security checklist** against the live service. The
   stack now runs, so this is unblocked — and defects 8–11 suggest the checklist
   will find things the suite cannot.
2. **Audit the other detectors for the same failure shape as defect 8.** Email
   was found by accident. Every recognizer that delegates validation to a
   third-party list or checksum deserves the same "what does it silently
   reject?" pass — `US_SSN` already hard-rejects published placeholders, which
   is the same mechanism pointed in a safer direction.
3. **Close the Phase 15 gaps** — integration tests against disposable Postgres
   and Redis, and move security assertions into `tests/security/`.
4. **Measure.** Every remaining item is measurement rather than construction:
   nothing has been benchmarked, the system has never run under concurrency, and
   the alert thresholds in `docs/observability.md` are still reasoned rather
   than derived. The outbound scan is now a second full detection pass on every
   request, which makes the latency question sharper than it was.
5. **Performance.** There is now an endpoint to measure and metrics to measure
   it with; the alert thresholds in `docs/observability.md` should be replaced
   with values this produces. Extraction and detection are benchmarked
   separately from the pipeline, per `docs/performance.md` §2.
6. **Populate the audit correlation HMACs**, or delete the columns. A field that
   is always null is worse than an absent one.
7. **Sweep the rest of the log call sites for defect 20.** The document path is
   fixed and asserted. Nothing yet proves that every *other* module's log fields
   survive the allowlist, and the failure mode is silent by construction.

---

## 7. ADR-0022: batch vault operations

The read path was always batched — `resolve_many` takes a set of tokens and
returns their originals in one round trip. The **write** path was not: the
tokenizer walked detected spans and awaited `get_or_create` once per span, so
protecting a message cost one Redis round trip per entity. Fine for a sentence,
arithmetically fatal for the 2,000-word document target in
[docs/performance.md](docs/performance.md).

What changed:

- **`TokenVault` now exposes `get_or_create_many` and no single-token write.**
  Removing the per-token method is the point — leaving it would leave the loop
  one call site away from coming back. A test asserts neither implementation
  has a `get_or_create` attribute.
- **The Redis implementation is one Lua script.** `WATCH`/`MULTI` over N
  fingerprint keys was the obvious alternative and is the wrong one: any single
  key changing aborts the whole batch, so contention would *grow* with batch
  size where per-token `WATCH` only ever aborted one token. Lua runs to
  completion with nothing interleaved.
- **The fingerprint index now stores a bare token id** rather than the full
  token, so the script can derive a record key from an index entry without
  parsing the token grammar in Lua. Session-scoped keys with a ≤2h TTL, so the
  format change needs no migration.
- **Duplicates collapse before the vault is touched.** A value repeated twenty
  times in one message is one entry, not twenty.
- **The tokenizer mints everything in one call, then splices.** Minting has no
  ordering requirement between spans; only splicing does, and it still runs
  right to left so offsets stay valid.

Measured on fakeredis, so the numbers describe this code rather than a network:
a 200-entity batch costs **0.83 ms per token** against the 5 ms target, and 200
repeats of one value cost 1.3 ms total. The round-trip count is the assertion
that holds on any hardware: **one, at every batch size from 1 to 200.**

Two caveats worth carrying:

- **`uv.lock` is stale.** `lupa` was added to the dev extras — fakeredis cannot
  execute `EVAL`/`EVALSHA` without a Lua runtime, so without it the vault suite
  fails at the first script call. `uv` is not on PATH on this machine, so the
  lock was not regenerated; run `uv lock` where it is. CI uses
  `uv sync --all-extras` without `--frozen` and the Dockerfile is `--no-dev`,
  so neither is blocked meanwhile.
- **The script has only been run against fakeredis**, which executes Lua through
  `lupa` rather than Redis's own interpreter. `tests/integration/test_vault_redis.py`
  covers `EVALSHA` caching, `NOSCRIPT` recovery, real atomicity across separate
  clients, and binary-safe envelope arguments — and skips without
  `TEST_REDIS_URL`. Given that four of eleven defects so far were only visible
  from a running container, treat "passes on fakeredis" as unfinished.

---

## 8. Build method

Built with parallel sub-agents over two waves, with a human-run integration pass
between them:

- **Wave 1** (6 agents, disjoint file ownership): policy, detection,
  tokenization, vault, repositories, providers.
- **Wave 2** (4 agents): auth, restoration, audit + privacy suite, pipeline.
- Cross-module seams were declared as `typing.Protocol` so no agent blocked on
  another, then reconciled during integration.

Defects 1, 2, 6 and 7 in §3 were all products of that parallelism — and all were
caught in the integration pass, not by the agents. The method works, but the
integration step is not optional.

## §6 Policy management (ADR-0037) — complete

Built on top of the existing policy engine. `PolicyDocument`, `PolicySnapshot`,
resolution, and the request pipeline are unchanged: they were already
configuration-driven, and this phase made them visible and editable rather than
reworking them.

**Verified 2026-08-07.** Backend: `ruff format`, `ruff check`, `mypy app`, 1737
tests. Frontend: `lint`, `typecheck`, 158 tests, `build`.

### What was built

Twelve endpoints under `/v1/policies` and `/v1/detectors/entities`; migration
`0004` adding `status`, `published_at`, and a one-draft-per-name partial unique
index; a detector catalog derived from `app.detection.entities`; authoring-time
validation and diff; audit events; three frontend routes with the draft and
publish workflow, version history, diff, and the test playground.

### Defects found building it

**Defect 21 — `datetime` imported under `TYPE_CHECKING`.** Pydantic resolves
response-model annotations at runtime when it builds the schema, so a name that
exists only for the type checker is not there when it looks. The whole router
was unreachable: `create_app().openapi()` raised, which meant *every* policy
route 500ed. `ruff` and `mypy --strict` both accepted the file. Found by
building the app and listing its routes, which is the only check that exercises
schema construction.

**Defect 22 — `vars()` on a `slots=True` dataclass.** `ValidationProblem` and
`FieldChange` are slotted, so they have no `__dict__`; `POST .../validate` and
`GET .../diff` returned `INTERNAL_ERROR`. Invisible to static checking, caught
by the API tests.

**Defect 23 — assumed HTTP status codes.** I wrote tests expecting 404 and 422.
This gateway maps `POLICY_NOT_FOUND` to **409** and `INVALID_REQUEST` to **400**,
matching how `/v1/chat` already reports them. The OpenAPI `responses` block had
been written to the same wrong assumption, so the documentation would have been
wrong in the same direction as the tests — a case where a test agreeing with the
docs proves nothing, because one was copied from the other.

**Defect 24 — a frontend test file that rendered once.** Eleven of twelve tests
stubbed the gateway and queried a page that had never been mounted. Every
failure read "unable to find element" rather than "you forgot to render".
Rendering now lives inside the helper that stubs.

**Defect 25 — the browser-persistence guard flagged its own documentation.**
`lib/persistence.test.ts` matched the bare identifier `localStorage`, so a
comment explaining that the playground never writes input to localStorage
tripped the guard enforcing that guarantee. Narrowed to require a property
access, with two new tests: one proving six real usage forms still trip it, one
proving prose does not. Loosening a guard without proving it still catches
things is how a guard quietly stops working.

**Defect 26 — the playground refused every policy nobody was editing.**
`POST /v1/policies/test` with no `version` looked only for an open draft and
raised `POLICY_NOT_FOUND` when there was none, which is the normal state of a
published policy. The page text promised the opposite ("detects against the open
draft if there is one, otherwise the active version"), so the documentation and
the code disagreed and the code was wrong.

Found by running the playground against the local stack, not by a test: the 34
API tests all supplied an explicit `version` or created a draft first, so none
of them exercised the one path an operator takes first.

Fixing it created a second-order problem worth recording. `_load_version` backs
both the playground and draft validation, so adding the fallback silently made
`POST .../validate` check the *active published version* when no draft existed —
answering "valid" to an operator asking about a draft they had not created.
Validation now looks the draft up directly.

The two behaviours are deliberately different:

| Endpoint | No explicit version |
|---|---|
| `POST /v1/policies/test` | open draft if present, otherwise the active published version |
| `POST /v1/policies/{name}/validate` | open draft only; `POLICY_NOT_FOUND` if there is none |

Both are pinned:
`tests/unit/test_api_policies.py::TestPlayground::test_it_falls_back_to_the_active_version_when_no_draft_is_open`
and
`::TestValidationAndDiff::test_validation_requires_a_draft_rather_than_checking_the_live_version`.

### Known limitations

- **One draft per policy, with no owner.** A second operator cannot start
  editing until the first publishes or discards, and there is no way to see who
  holds it.
- **No approval workflow, scheduling, or rollback automation.** Reverting means
  opening a draft, editing it back, and publishing — which produces a new
  version rather than pretending the change never happened.
- **Unsaved draft edits are lost on reload**, because they live in component
  state and browser storage is deliberately unused for anything a caller typed.
- **Discarded drafts leave gaps in version numbers.** Preferable to reusing a
  number that already appeared in a log line.
- **`CUSTOM_RECOGNIZER_TYPES` is hand-maintained.** Introspecting the recognizer
  registry would need a spaCy load on a cheap read, so a new custom recognizer
  whose type is not added there is reported as built-in.
- **The deployed demo API key predates these scopes** and will be refused by the
  policy endpoints until it is re-issued.
- **The JSON policy preview from architecture.md §22.10 was not built.** The
  entity table and diff cover what it was for.

## §7 Protected Payload Preview

Added so the demo can show, rather than assert, that values were transformed
before the provider call. `ChatResponse.protected_preview` carries the protected
text with every token identifier masked, per-type counts of what was applied,
and the outbound scan outcome.

**Verified 2026-08-08.** Backend: `ruff format-check`, `ruff check`, `mypy app`,
1759 unit/privacy/security tests. Frontend: `lint`, `typecheck`, 165 tests,
`build`.

### The constraint this had to work within

architecture.md 22.6 forbade the provider request body in the Privacy Inspector
outright, and allowed a "Protected Prompt Preview" only behind a privileged
endpoint disabled in production. Rather than override an accepted rule silently,
22.6 is narrowed: a masked preview is permitted, gated by
`PROTECTED_PREVIEW_ENABLED`, which defaults to off.

Masking happens in `app/pipeline/preview.py`, on the server. The browser is
never sent a full token and never asked to hide one -- a client that had to mask
would still hold the identifier in memory, in the network tab, and in any error
report the page produced.

### Deliberate limits

- **The document path returns no preview text.** It would render extracted
  document body, which this panel has never shown and which ADR-0030 keeps out
  of storage. Counts and the attestation still describe what happened.
- **Actions are read from the tokens, not from the policy.** A value scoring
  below its threshold is left in place whatever the policy says about its type,
  so reading the policy would report protection that did not happen.
- **`pseudonymize` is reported as `tokenize`.** Both mint a resolvable token
  with the same grammar, and the token in the text is what actually happened;
  guessing from the policy would be an inference, not a reading.
- **Bounded at 600 characters**, cut on a mask boundary so a truncation never
  leaves a dangling delimiter that reads as a malformed token.
