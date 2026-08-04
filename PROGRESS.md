# Build Progress

Status of the Secure AI Gateway against the phase plan in
[implementation.md](implementation.md).

**As of 2026-08-04** — 20 commits · 87 modules under `app/` · **776 tests passing,
7 skipped** · **96% coverage** (target 90%) · `mypy --strict` clean · ruff clean.

The per-phase checkboxes in `implementation.md` are kept in sync with this file.
Where the two disagree, trust the test suite.

---

## 1. Phase status

| Phase | Name | Tasks | State |
| --- | --- | --- | --- |
| 0 | Repository bootstrap | 12/12 | ✅ Complete |
| 1 | Configuration and lifecycle | 9/11 | ⚠️ Lifespan opens no clients |
| 2 | PostgreSQL, migrations, repositories | 7/7 | ✅ Complete |
| 3 | Authentication, scopes, rate limiting | 10/10 | ✅ Complete |
| 4 | Policy engine | 9/9 | ✅ Complete |
| 5 | Detection engine | 14/14 | ✅ Complete |
| 6 | Tokenization | 10/10 | ✅ Complete |
| 7 | Encrypted Redis vault | 12/12 | ✅ Complete |
| 8 | Secure pipeline orchestration | 10/10 | ✅ Complete |
| 9 | Provider abstraction and OpenAI adapter | 11/11 | ✅ Complete |
| 10 | Output parsing and restoration | 10/10 | ✅ Complete |
| 11 | **API endpoints** | 2/6 | ❌ **Only health probes exist** |
| 12 | Audit logging | 7/8 | ⚠️ Retention docs missing |
| 13 | **Observability** | 0/7 | ❌ Not started |
| 14 | Docker Compose and local ops | 11/11 | ⚠️ Written, never executed |
| 15 | Test strategy | mixed | ⚠️ See §4 |
| 16 | Performance tests | 0/6 | ❌ Not started |
| 24 | Manual security verification | 0/16 | ❌ Blocked on Phase 11 |

**Roughly 11 of 16 phases are done.** The critical path to a service you can
`curl` is Phase 11 plus the two open Phase 1 lifespan items.

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
| `app/api/`, `app/observability/` | 17 | Request id, error envelope, body-size limit, allowlist logging |
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

---

## 4. Known gaps and caveats

Read these before trusting a checkmark.

- **Phase 14 is written but never executed.** `docker compose up --build` has
  not been run. The Dockerfile and compose file are complete and hardened, but
  "the stack starts and health becomes ready" is unverified.
- **Phase 2 migrations were verified by the agent that wrote them, not
  independently.** There is no local PostgreSQL, so the 7 integration tests skip
  here. They run in CI.
- **Phase 15 integration coverage is thin.** Only migrations. The plan calls for
  full-flow, TTL expiry, concurrent token creation, session deletion, and
  dependency-outage integration tests.
- **Security assertions are spread through module tests** rather than collected
  in the `tests/security/` tree the plan specifies. The coverage exists; the
  organisation does not match §20.
- **The privacy regression suite hand-rolls restoration**, because
  `app/restoration/` did not exist when it was written. It should be rewired to
  the real module.
- **No `/metrics` endpoint.** Prometheus metrics are defined inside vault, auth,
  and audit, but nothing exposes them — there is no `generate_latest` call in
  `app/`.
- **`app/main.py` lifespan is a stub.** It opens no Redis or PostgreSQL client,
  so nothing is wired into a running application yet.

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

# What routes actually exist (currently: two)
./.venv/Scripts/python.exe -c "from app.main import create_app; print(sorted(create_app().openapi()['paths']))"
```

`make <target>` also works where GNU make is available; `python tasks.py
<target>` runs the identical commands on Windows.

---

## 6. Next steps, in order

1. **Phase 11 — API endpoints**, plus the two open Phase 1 lifespan items.
   `POST /v1/chat`, `POST /v1/detect`, `DELETE /v1/sessions/{id}`, and the
   composition root that opens Redis and PostgreSQL and injects the already-built
   services. Everything this needs exists and is tested; it is wiring.
2. **Phase 13 — observability.** Expose `/metrics`, add real readiness checks,
   optional OTel.
3. **Close the Phase 15 gaps** — integration tests against disposable Postgres
   and Redis, and move security assertions into `tests/security/`.
4. **Run the stack.** `docker compose up --build`, then work the §24 manual
   security checklist against a live service.
5. **Phase 16 — performance**, once there is an endpoint to measure.

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
