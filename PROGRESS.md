# Build Progress

Status of the Secure AI Gateway against the phase plan in
[implementation.md](implementation.md).

**As of 2026-08-04** — 26 commits · 96 modules under `app/` · **882 tests passing,
7 skipped** · **97% coverage** (target 90%) · `mypy --strict` clean · ruff clean.

Six routes are live: `/v1/chat`, `/v1/detect`, `/v1/sessions/{session_id}`,
`/health/live`, `/health/ready`, `/metrics`.

**The stack has now been run.** `docker compose up --build` from an empty
volume, migrations applied, seeded, and real requests served end to end with
Prometheus scraping. That run produced four defects the test suite could not
see — see §3, defects 8–11.

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
| 15 | Test strategy | mixed | ⚠️ See §4 |
| 16 | Performance tests | 0/6 | ❌ Not started |
| 24 | Manual security verification | 0/16 | ❌ Blocked on running the stack |

**13 of 16 backend phases are done.** The service now answers requests and
exports metrics. What remains is verification against a running stack rather
than construction: nobody has yet executed `docker compose up`.

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
| `tests/privacy/` | 19 | Canary regression suite and default-policy threshold checks |

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
- **Four of eleven defects were only visible from a running container.**
  Defects 8–11 all passed 882 tests, `mypy --strict`, and ruff. Two of them
  (9 and 10) meant the service could not serve a single request; one (8) was a
  silent leak. A green suite says the code is consistent with itself, not that
  the artifact you ship works.
- **A test that encodes a known gap should assert both directions.** The canary
  suite documented "the real detector cannot see this" — correct when written,
  and it failed loudly the moment the detector improved, which is what a good
  test does. It now records coverage in `REAL_DETECTOR_COVERS` and asserts both
  halves, so a regression that reopens the leak cannot pass quietly.

---

## 4. Known gaps and caveats

Read these before trusting a checkmark.

- **Phase 2 migrations now run against real PostgreSQL**, applied inside the
  stack (`alembic upgrade head` → `Running upgrade -> 0001`) against an empty
  volume, producing all five tables. The 7 integration tests still skip here
  for want of a host database; they run in CI.
- **The stack has been run, but not exercised under load.** One cold start,
  migrations, seed, and a handful of hand-driven requests — enough to prove the
  path works, not enough to characterise it. Nothing here has seen concurrency.
- **`test_outbound_payload_carries_tokens_and_no_originals` is timing-sensitive.**
  It failed twice while a Docker build was saturating the CPU, raising
  `ProviderTimeoutError` from the adapter's own deadline against a `respx` mock
  that never touches the network, and passes consistently on an idle machine.
  The test asserts a privacy property worth keeping, so the fix is to make the
  adapter's deadline injectable for tests rather than to widen it globally —
  not yet done. Treat a lone failure here as machine load until proven
  otherwise.
- **Phase 15 integration coverage is thin.** Only migrations. The plan calls for
  full-flow, TTL expiry, concurrent token creation, session deletion, and
  dependency-outage integration tests.
- **Security assertions are spread through module tests** rather than collected
  in the `tests/security/` tree the plan specifies. The coverage exists; the
  organisation does not match §20.
- **The privacy regression suite hand-rolls restoration**, because
  `app/restoration/` did not exist when it was written. It should be rewired to
  the real module.
- **Tracing is not implemented.** `OTEL_EXPORTER_OTLP_ENDPOINT` sits in
  `Settings` and nothing reads it. It was optional in the plan; the setting
  existing without an implementation is the misleading part, and it is called
  out in `docs/observability.md` §5 for that reason.
- **The audit correlation HMACs are never populated.** `CorrelationHasher`
  exists and is tested, but the pipeline does not write `prompt_hmac` or
  `response_hmac`, so both are null in a live audit row.
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

# The canary suite specifically
./.venv/Scripts/python.exe -m pytest tests/privacy -m privacy -v

# Coverage against the 90% target
./.venv/Scripts/python.exe -m pytest tests --cov=app --cov-report=term

# Types and lint
./.venv/Scripts/python.exe -m mypy app
./.venv/Scripts/python.exe -m ruff check app tests scripts

# What routes actually exist (currently: six)
./.venv/Scripts/python.exe -c "from app.main import create_app; print(sorted(create_app().openapi()['paths']))"

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
```

`make <target>` also works where GNU make is available; `python tasks.py
<target>` runs the identical commands on Windows.

---

## 6. Next steps, in order

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
4. **Phase 16 — performance.** There is now an endpoint to measure and metrics
   to measure it with; the alert thresholds in `docs/observability.md` should be
   replaced with values this produces.
5. **Populate the audit correlation HMACs**, or delete the columns. A field that
   is always null is worse than an absent one.

---

## 7. Build method

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
