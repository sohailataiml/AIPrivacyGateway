# Secure AI Gateway — Implementation Plan

**Document:** `implementation.md`  
**Execution target:** Claude Code  
**Depends on:** `architecture.md`  
**Implementation style:** Incremental, test-first, security-first  
**Primary language:** Python  
**Initial API framework:** FastAPI

---

## 1. Instructions to Claude Code

Read `architecture.md` completely before changing code.

Read `docs/adr/README.md` and every ADR with status **Accepted** before changing architecture-sensitive code.

Implement phases in order. At the end of every phase:

1. Run formatting, linting, static type checking, unit tests, and relevant integration tests.
2. Fix all failures before continuing.
3. Update the checklist in this document.
4. Keep commits or logical change groups small.
5. Do not add features that are outside the current phase.
6. Do not log prompt bodies, response bodies, mappings, credentials, or full security tokens.
7. Do not call an external provider in tests.
8. Use interfaces and fakes so tests remain deterministic.
9. Fail closed whenever privacy processing cannot be completed.
10. Never bypass detection or tokenization as a fallback.

Preferred commands may change with tool versions, but the repository must expose stable task commands through `Makefile` or `justfile`:

```bash
make install
make format
make lint
make typecheck
make test
make test-integration
make test-privacy
make run
make compose-up
make compose-down
```

---

## 2. Version 1 Scope

Version 1 must include:

- FastAPI application.
- API-key authentication.
- Tenant-aware request context.
- Policy model and default policy.
- Presidio-based detection with custom regex recognizers.
- Reversible opaque tokenization.
- Application-encrypted Redis vault.
- Synchronous OpenAI provider adapter.
- Response token restoration.
- Privacy-safe audit records in PostgreSQL.
- Health and Prometheus metrics.
- Docker Compose.
- Automated tests.
- Documentation and sample requests.

Version 1 must not include:

- Kubernetes or Helm deployment.
- Streaming responses.
- Multiple external providers.
- File or image processing.
- OIDC login.
- Automated medical classification claims.
- An LLM-based detector.

---

## 3. Technology Baseline

Use currently supported stable releases at implementation time and pin them in the lock file.

Recommended packages:

```text
fastapi
uvicorn
pydantic
pydantic-settings
httpx
openai
presidio-analyzer
presidio-anonymizer
spacy
redis
sqlalchemy
asyncpg
alembic
cryptography
prometheus-client
structlog
tenacity
orjson
python-ulid or ulid-py
```

Development packages:

```text
pytest
pytest-asyncio
pytest-cov
respx
hypothesis
ruff
mypy
types-redis if needed
bandit
pip-audit or equivalent
```

Use `uv` for dependency and environment management unless the existing project already standardizes on Poetry. Do not mix package managers.

---

## 4. Coding Rules

- Python 3.12 or newer stable version supported by all chosen libraries.
- Full type annotations for public functions.
- Async I/O for HTTP, Redis, and PostgreSQL.
- Pydantic models at API boundaries.
- Domain dataclasses or Pydantic models for internal contracts.
- Repository and provider interfaces defined with `Protocol`.
- No global mutable service objects except safely initialized application dependencies.
- No raw SQL string interpolation.
- No broad `except Exception` unless immediately converted to a safe domain error and logged without sensitive content.
- No `print`.
- No request-body logging middleware.
- No secrets in test fixtures.
- UTC-aware timestamps.
- UUIDs for durable IDs; random ULIDs are acceptable for token IDs.
- Error responses use stable machine-readable codes.
- Security-sensitive comparison uses constant-time helpers where applicable.

---

## 5. Phase 0 — Repository Bootstrap

### Tasks

- [x] Create directory structure from `architecture.md`.
- [x] Initialize `pyproject.toml`.
- [x] Configure Ruff formatting and linting.
- [x] Configure mypy in strict or near-strict mode.
- [x] Configure pytest and coverage.
- [x] Add `.gitignore`.
- [x] Add `.env.example` with variable names and safe placeholders.
- [x] Add `Makefile`.
- [x] Add pre-commit configuration.
- [x] Add CI workflow for lint, type check, tests, dependency audit, and secret scan.
- [x] Add `README.md` with local setup instructions.
- [x] Add a minimal `app/main.py`.

### Required files

```text
pyproject.toml
uv.lock
Makefile
.env.example
.gitignore
.pre-commit-config.yaml
.github/workflows/ci.yml
app/__init__.py
app/main.py
tests/unit/test_bootstrap.py
```

### Acceptance criteria

- `make install` succeeds.
- `make format`, `make lint`, and `make typecheck` succeed.
- `make test` succeeds.
- `GET /health/live` returns `200`.
- CI executes without requiring real provider credentials.

---

## 6. Phase 1 — Configuration and Application Lifecycle

### Tasks

- [x] Implement typed settings in `app/config/settings.py`.
- [x] Add environment profiles: `local`, `test`, `production`.
- [x] Validate required production secrets.
- [x] Configure FastAPI lifespan.
- [x] Initialize Redis and PostgreSQL clients during startup.
- [x] Close resources during shutdown.
- [x] Add request ID middleware.
- [x] Add safe structured logging.
- [x] Add global exception handlers.
- [x] Add CORS disabled by default.
- [x] Add body-size enforcement.

### Settings rules

- Development may use a documented local key.
- Production must reject default or short encryption keys.
- Settings representations must mark secret fields as hidden.
- Never serialize all settings into logs.

### Error format

```json
{
  "error": {
    "code": "VAULT_UNAVAILABLE",
    "message": "The secure mapping service is unavailable.",
    "request_id": "uuid"
  }
}
```

### Acceptance criteria

- Invalid production configuration prevents startup.
- Request IDs are returned in `X-Request-ID`.
- Exceptions do not echo request content.
- Unit tests prove secret settings are not included in logs or model repr output.
- Oversized bodies are rejected before expensive processing.

---

## 7. Phase 2 — PostgreSQL, Migrations, and Repositories

### Tasks

- [x] Configure async SQLAlchemy engine and sessions.
- [x] Configure Alembic.
- [x] Create migrations for tenants, API keys, policies, provider configs, and audit events.
- [x] Implement repository interfaces.
- [x] Add transaction helper.
- [x] Seed one local tenant and default policy through an idempotent script.
- [x] Store only provider secret references, never provider secrets.

### API key storage

Generate raw keys with at least 32 random bytes.

Suggested display format:

```text
sgw_live_<base64url-random>
```

Store:

- prefix for operator identification
- HMAC or password-hash representation
- pepper from environment
- status and scopes

Do not store the raw key.

### Acceptance criteria

- Migrations upgrade and downgrade successfully in test environments.
- Unique constraints prevent duplicate policy versions.
- Repository tests verify tenant filtering.
- A deliberate cross-tenant lookup returns no result.
- Database logs do not contain raw API keys.

---

## 8. Phase 3 — Authentication, Authorization, and Rate Limiting

### Tasks

- [x] Parse `Authorization: Bearer <api-key>`.
- [x] Resolve API key by prefix.
- [x] Verify its hash safely.
- [x] Reject expired, disabled, or unknown keys.
- [x] Construct immutable `Principal`.
- [x] Implement scope dependency.
- [x] Update `last_used_at` asynchronously or with bounded frequency.
- [x] Implement Redis-backed fixed-window or sliding-window rate limiting.
- [x] Rate limit by tenant and API key.
- [x] Add authentication and rate-limit metrics.

### Security requirements

- Authentication failures return the same public message.
- Do not reveal whether a key prefix exists.
- Never include the supplied credential in logs.
- Rate-limit keys must not contain the raw API key.
- Fail closed for protected endpoints when the rate-limit backend is unavailable, unless an explicit policy says otherwise.

### Tests

- Missing header.
- Wrong scheme.
- Unknown key.
- Incorrect secret with valid prefix.
- Expired key.
- Disabled key.
- Missing scope.
- Valid key.
- Rate limit exceeded.
- Cross-tenant access attempt.

### Acceptance criteria

- Protected endpoints reject unauthenticated access.
- Scope checks return `403`.
- Timing differences are minimized for invalid-key cases.
- Authentication logs contain only request ID and generic reason code.

---

## 9. Phase 4 — Policy Engine

### Tasks

- [x] Define policy schema.
- [x] Implement default policy.
- [x] Implement tenant policy repository.
- [x] Resolve active policy snapshot per request.
- [x] Validate entity actions and thresholds.
- [x] Validate provider and model allowlists.
- [x] Add policy version to request context and audit metadata.
- [x] Cache policy documents briefly without caching secrets.
- [x] Add policy-validation command.

### Example policy

```json
{
  "schema_version": 1,
  "name": "default",
  "session_ttl_seconds": 1800,
  "max_entities": 500,
  "providers": {
    "openai-primary": {
      "models": ["general-chat"]
    }
  },
  "entities": {
    "EMAIL_ADDRESS": {"action": "tokenize", "min_score": 0.7},
    "PHONE_NUMBER": {"action": "tokenize", "min_score": 0.4},
    "US_SSN": {"action": "block", "min_score": 0.5},
    "CREDIT_CARD": {"action": "block", "min_score": 0.5},
    "PERSON": {"action": "tokenize", "min_score": 0.75},
    "LOCATION": {"action": "tokenize", "min_score": 0.8}
  },
  "unknown_output_token_action": "preserve"
}
```

### Acceptance criteria

- Invalid policies cannot become active.
- Provider or model outside allowlist is rejected before detection and provider invocation.
- Policy resolution always produces a versioned immutable object.
- Policy tests cover every action.

---

## 10. Phase 5 — Detection Engine

### Tasks

- [x] Define detector interface and domain models.
- [x] Integrate Presidio analyzer.
- [x] Configure spaCy model through setup documentation.
- [x] Add custom regex recognizers for:
  - [x] API keys or bearer tokens.
  - [x] Medical record number sample format.
  - [x] Health plan identifier sample format.
  - [x] Enterprise account number sample format.
- [x] Add allowlist support.
- [x] Add confidence thresholds.
- [x] Implement deterministic overlap resolution.
- [x] Add language parameter with English enabled.
- [x] Add maximum-entity guard.
- [x] Record recognizer name only in diagnostic mode.

### Detector input contract

```python
async def detect(
    text: str,
    language: str,
    requested_entities: set[str] | None,
) -> list[DetectedEntity]
```

### Important implementation details

- Keep original character offsets.
- Reject invalid spans.
- Never return original values from public diagnostic endpoints by default.
- Treat generic medical condition detection as unsupported unless a dedicated recognizer is implemented and evaluated.
- Compile regex patterns once.
- Add checksum validation for credit cards.
- Add context terms for ambiguous identifiers.

### Test corpus

Create synthetic fixtures only:

- Emails.
- US phone numbers.
- SSNs.
- Credit cards passing and failing checksum.
- Names and locations.
- Overlapping entities.
- Repeated entities.
- Unicode names.
- False-positive allowlist examples.
- Secrets embedded in JSON and code.
- Empty and whitespace-only strings.
- Very long safe text.
- Maximum entity count.

### Acceptance criteria

- Detection returns stable sorted spans.
- Overlap resolution is deterministic.
- The detector meets configured thresholds.
- False-positive controls work.
- No fixture contains a real person's sensitive data.

---

## 11. Phase 6 — Tokenization

### Tasks

- [x] Define exact token grammar.
- [x] Implement cryptographically random token IDs.
- [x] Implement entity-specific normalization.
- [x] Implement HMAC fingerprinting.
- [x] Implement right-to-left replacement.
- [x] Implement action handlers for allow, tokenize, redact, pseudonymize, and block.
- [x] Return a protected type that cannot be confused with raw input.
- [x] Add repeated-value token reuse within a session.
- [x] Enforce maximum entity count.
- [x] Add property-based tests for offset safety.

### Token grammar

```regex
⟦SGW:(?P<type>[A-Z0-9_]{1,64}):(?P<id>[0-9A-HJKMNP-TV-Z]{26})⟧
```

Use a parser, not only a loose regex, for restoration.

### Replacement invariants

- Text outside selected spans remains byte-for-byte equivalent after Unicode encoding decisions.
- Every tokenized span has exactly one vault mapping.
- Redacted spans have no mapping.
- Blocked spans cause no provider call.
- Repeated normalized value plus entity type returns the same token within a session.
- The same value in a different session produces a different token.
- Different entity types for identical text produce different tokens.

### Acceptance criteria

- Unit tests cover all invariants.
- Hypothesis tests cover random spans and Unicode.
- Tokens are not sequential or guessable.
- A protected request cannot be instantiated without pipeline metadata.

---

## 12. Phase 7 — Encrypted Redis Vault

### Tasks

- [x] Define vault interface.
- [x] Implement AES-256-GCM envelope encryption.
- [x] Load active key and key ring through settings.
- [x] Include associated data.
- [x] Implement token record storage.
- [x] Implement fingerprint-to-token index.
- [x] Implement atomic create-or-reuse operation using Lua or transaction.
- [x] Apply TTL to all keys.
- [x] Implement batch retrieval.
- [x] Implement session deletion.
- [x] Implement key-rotation-compatible decryption.
- [x] Add vault latency and result metrics.

### Vault interface

```python
class TokenVault(Protocol):
    async def get_or_create(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        entity_type: str,
        normalized_hmac: str,
        original_value: str,
        ttl_seconds: int,
    ) -> str:
        ...

    async def resolve_many(
        self,
        *,
        tenant_id: UUID,
        session_id: UUID,
        tokens: set[str],
    ) -> dict[str, str]:
        ...

    async def delete_session(self, *, tenant_id: UUID, session_id: UUID) -> int:
        ...
```

### Security tests

- Redis values do not contain plaintext originals.
- Wrong key cannot decrypt.
- Modified ciphertext fails authentication.
- Wrong tenant or session associated data fails.
- Expired token cannot resolve.
- Cross-session token cannot resolve.
- Cross-tenant token cannot resolve.
- Concurrent identical inserts return one stable token.
- Session deletion removes all mappings.

### Acceptance criteria

- `redis-cli` inspection shows encrypted envelopes only.
- Every key has TTL.
- Redis outage prevents provider invocation.
- No plaintext mapping appears in logs during encryption errors.

---

## 13. Phase 8 — Secure Pipeline Orchestration

### Tasks

- [x] Implement pipeline service.
- [x] Process system, user, and assistant message content.
- [x] Resolve one session ID.
- [x] Apply policy and detection.
- [x] Persist mappings before provider invocation.
- [x] Produce `ProtectedChatRequest`.
- [x] Add privacy metadata counters.
- [x] Add pipeline timeout.
- [x] Add bounded concurrency for provider calls.
- [x] Add fail-closed errors.

### Pipeline pseudocode

```python
async def invoke(raw_request: ChatRequest, principal: Principal) -> ChatResponse:
    policy = await policy_service.resolve(principal, raw_request)
    session_id = session_service.resolve(raw_request.session_id, principal)

    protected_messages = []
    aggregate = PrivacySummary()

    for message in raw_request.messages:
        entities = await detector.detect(
            message.content,
            language="en",
            entity_types=policy.entity_types,
        )
        transformed = await tokenizer.transform(
            tenant_id=principal.tenant_id,
            session_id=session_id,
            text=message.content,
            entities=entities,
            policy=policy,
        )
        protected_messages.append(
            ChatMessage(role=message.role, content=transformed.text)
        )
        aggregate.add(transformed.summary)

    protected_request = ProtectedChatRequest(...)
    provider_response = await provider.complete(protected_request)
    restored = await output_pipeline.process(...)
    await audit_service.record(...)
    return restored
```

### Acceptance criteria

- No code path calls provider before mappings are persisted.
- Provider mocks never receive raw detected values.
- Block policy stops before vault and provider where possible.
- The request and session IDs remain stable through all stages.
- Integration tests prove fail-closed behavior for every dependency.

---

## 14. Phase 9 — OpenAI Provider Adapter

### Tasks

- [x] Define provider registry.
- [x] Implement `OpenAIProvider`.
- [x] Map internal model alias to provider model ID.
- [x] Use the current official OpenAI text generation interface supported by the installed SDK.
- [x] Configure timeouts.
- [x] Configure bounded retry for transient network and selected `429` or `5xx` responses.
- [x] Disable storage where supported and required by policy.
- [x] Map provider errors into domain errors.
- [x] Capture usage metadata.
- [x] Add HTTP mocking with `respx` or SDK transport fakes.
- [x] Ensure provider client never logs request content.

### Provider safety rules

- No arbitrary base URL from request.
- No arbitrary headers from request.
- No provider key in response or logs.
- No raw request model accepted by adapter.
- Retry count default: 2.
- Do not retry invalid input, authentication failure, or policy block.
- Apply overall deadline in addition to connection and read timeouts.

### Tests

- Successful response.
- Timeout.
- Connection failure.
- Rate limit then success.
- Permanent rate limit.
- Provider `4xx`.
- Provider `5xx`.
- Invalid response structure.
- Usage absent.
- Verify exact outbound payload contains protected tokens and excludes originals.

### Acceptance criteria

- All tests run with mocked transport.
- Provider adapter is replaceable through the registry.
- No external network call occurs in CI.

---

## 15. Phase 10 — Output Parsing and Restoration

### Tasks

- [x] Implement strict token parser.
- [x] Buffer and parse synchronous response.
- [x] Batch vault resolution.
- [x] Restore only complete exact tokens.
- [x] Preserve unknown tokens by default.
- [x] Add unknown-token count.
- [x] Enforce output-size limit.
- [x] Add optional output scan.
- [x] Reject malformed provider payloads.
- [x] Prevent recursive or repeated restoration errors.

### Restoration algorithm

1. Parse exact gateway token candidates.
2. Deduplicate candidates.
3. Resolve candidates in one vault call.
4. Replace known tokens from right to left or through parser segments.
5. Preserve unknown tokens.
6. Run optional output policy.
7. Return restored text only to authorized request principal.

### Tests

- One token.
- Multiple tokens.
- Repeated token.
- Adjacent tokens.
- Token split-like malformed syntax.
- Unknown token.
- Token from another session.
- Token from another tenant.
- Natural text that resembles part of token syntax.
- Provider tries to alter type while retaining ID.
- Output contains newly generated email address.
- Vault unavailable after provider response.

### Acceptance criteria

- Cross-session restoration is impossible.
- Unknown tokens remain protected.
- No global lookup exists.
- Output restoration never searches by token ID without tenant and session.

---

## 16. Phase 11 — API Endpoints

### Implement

- [x] `POST /v1/chat`
- [x] `POST /v1/detect`
- [x] `DELETE /v1/sessions/{session_id}`
- [x] `GET /health/live`
- [x] `GET /health/ready`
- [x] `GET /metrics`

### `POST /v1/chat`

Requirements:

- `chat:invoke` scope.
- Valid provider/model alias.
- Idempotency key support is optional in v1; do not pretend requests are idempotent.
- Return privacy summary without entity values.
- Return `Cache-Control: no-store`.
- Add standard security headers.

### `POST /v1/detect`

Requirements:

- `detect:invoke` scope.
- Return offsets, type, score, and action.
- Do not return matched text unless an explicit privileged diagnostic configuration is enabled.
- Never enable matched-text return in production by default.

### `DELETE /v1/sessions/{session_id}`

Requirements:

- `sessions:delete` scope.
- Tenant-scoped.
- Idempotent.
- Return `204`.

### Acceptance criteria

- OpenAPI schema is generated.
- Examples use synthetic data.
- Error codes are documented.
- Every protected endpoint has authentication and scope tests.
- Responses include `X-Request-ID` and `Cache-Control: no-store`.

---

## 17. Phase 12 — Audit Logging

### Tasks

- [x] Implement audit event model and repository.
- [x] Add bounded asynchronous queue.
- [x] Record request outcome and privacy counts.
- [ ] HMAC prompt and response for correlation. (CorrelationHasher exists; the pipeline does not populate prompt_hmac/response_hmac -- confirmed null in a live audit row)
- [x] Store policy version.
- [x] Add audit failure metric.
- [x] Add configurable fail-open or fail-closed audit behavior; production default should be explicit.
- [ ] Add retention documentation.

### Prohibited fields

- raw message content
- raw response content
- original values
- decrypted mappings
- full gateway tokens
- API keys
- provider secrets

### Privacy test

Create a test that:

1. Sends a prompt with multiple synthetic sensitive values.
2. Runs the entire pipeline.
3. Reads all captured logs, audit rows, traces, and mocked provider payloads.
4. Asserts:
   - originals are absent from logs, audit, and traces;
   - originals are absent from provider payload;
   - originals are present only in authorized final response;
   - Redis stores no plaintext.

### Acceptance criteria

- Privacy test passes.
- Audit query indexes support timestamp and tenant filtering.
- Audit errors never log raw event payloads if that payload could contain future unsafe fields.

---

## 18. Phase 13 — Observability

### Tasks

- [x] Add Prometheus metrics from architecture specification. (Two documented
      deviations: `model` is not a provider label and `entity_type` is not a
      vault label, both because those strings are caller-supplied at the point
      of recording. See `docs/observability.md` §1.)
- [x] Add safe structured logs.
- [ ] Add optional OpenTelemetry tracing. (`OTEL_EXPORTER_OTLP_ENDPOINT` exists
      in `Settings`; nothing reads it. No dependency, no instrumentation.)
- [x] Add readiness checks.
- [x] Add dependency status without exposing credentials or hosts.
- [ ] Add sample Grafana dashboard JSON only if time permits.
- [x] Add alert recommendations to README. (In `docs/observability.md` §4,
      linked from the README index rather than inlined into it.)

### Suggested alerts

- Elevated `5xx`.
- Detector or vault unavailability.
- Unknown output token spike.
- Audit queue saturation.
- Provider timeout spike.
- Rate-limit spike.
- Detection latency regression.
- Redis memory pressure.

### Acceptance criteria

- Metrics have bounded cardinality.
- No identifier or sensitive value appears as a label.
- Readiness fails when required dependencies are unavailable.
- Liveness remains independent from dependencies.

---

## 19. Phase 14 — Docker Compose and Local Operations

### Services

```yaml
services:
  gateway:
  postgres:
  redis:
  prometheus:
```

Grafana is optional for version 1.

### Tasks

- [x] Create multi-stage Dockerfile.
- [x] Run as non-root.
- [x] Add health check.
- [x] Use read-only filesystem where practical.
- [x] Drop Linux capabilities.
- [x] Mount only required writable temporary directories.
- [x] Create Docker Compose configuration.
- [x] Add migration startup command or explicit documented migration step.
- [x] Add seed script.
- [x] Add local mock-provider option for demos.
- [x] Ensure local default does not accidentally call a paid provider.

### Acceptance criteria

- `docker compose up --build` starts the stack.
- Health endpoint becomes ready.
- Demo request works against mock provider.
- Container runs as non-root.
- Image does not include `.env`, tests containing secrets, or build caches.

**Verified 2026-08-04, all five.** Cold start from an empty volume;
`/health/ready` returns `{"redis":"up","database":"up"}`; a `POST /v1/chat`
against the mock provider tokenized and restored two entities; the process runs
as `uid=10001(gateway)`; `/app` contains only `alembic.ini`, `app`,
`migrations`, and `scripts`. Getting there took four fixes — see PROGRESS.md
§3, defects 8–11. The migration step is `make compose-migrate`, which runs
inside the stack: the compose database publishes no host port, so the host-run
`make migrate` cannot reach it.

---

## 20. Phase 15 — Secure Document Storage

Storage only. Extraction, segmentation, detection, tokenization, and restoration
for documents are **not** in this phase, and the code contains no partial
version of them — no unused status member, no dead column, no stub that returns
`NotImplemented`. See ADR-0020, ADR-0021, ADR-0027, and
`docs/document-processing.md`.

### Tasks

- [x] Add `app/documents/` with a `DocumentStore` Protocol, an aioboto3
      S3-compatible adapter, and an in-memory fake.
- [x] Chunked AES-256-GCM with per-document HKDF-SHA256 data keys.
- [x] Boundary validation: filename, type (extension + MIME + magic bytes),
      and length (declared and streamed).
- [x] Streaming upload and download, with S3 multipart past the part threshold
      and explicit abort on failure or cancellation.
- [x] Opaque storage keys; the object store is never told the real content type.
- [x] Encrypted filename column; tenant- and user-scoped repository.
- [x] Four routes under `/v1/documents`, with their own scopes.
- [x] Alembic migration `0002_documents`, verified in both directions.
- [x] MinIO and a bucket-initialization service in Docker Compose (ADR-0027).
- [x] Settings, production hardening checks, and `.env.example` entries.
- [x] Unit, security, privacy, and MinIO integration suites.
- [x] CI runs the MinIO suite and fails if it would skip.
- [ ] Retention enforcement. Documents persist until deleted.
- [ ] Key rotation tooling. The format supports it; nothing drives it.

### Deviations worth knowing

- **Routes are `/v1/documents`, not `/documents`.** Every other route in the
  gateway is versioned, and an unversioned sibling to `/v1/chat` reads as a bug.
- **`user_id` is the API key id.** The gateway authenticates keys, not people.
  Two keys in one tenant are two principals and cannot read each other's
  documents. `app/api/v1/documents.py::_user_id` is the single place that
  changes when a user model arrives.
- **`DOCUMENTS_ENABLED` gates both the routes and the configuration
  requirement**, so a deployment that does not accept uploads is not forced to
  configure a bucket.

### Acceptance criteria

- A document round-trips through real MinIO, sealed, via multipart.
- The stored object contains no plaintext, and the object key names nothing.
- Another tenant, another user, and an unknown id all get the same answer.
- A copy of one principal's object under another's key fails to authenticate.
- No failure leaves a row claiming `stored` without an object.
- An interrupted or cancelled multipart upload leaves no open upload behind.
- No canary value reaches a log line, a SQL statement, a metric, a response, or
  an object key.

**Verified 2026-08-05.** All seven, against a live MinIO rather than the fake.
Getting there found three more defects — an integration fixture that had never
executed because it patched a `__slots__` class, filename validation that
accepted bidirectional override characters, and a canary sweep that was reading
an empty log because application startup removes pytest's capture handler. See
PROGRESS.md.

---


## 17. Phase 16 — Frontend Bootstrap

### Tasks

- [ ] Create `frontend/` as a Next.js TypeScript application using the App Router.
- [ ] Configure Tailwind CSS and accessible UI primitives.
- [ ] Configure ESLint, formatting, TypeScript strict mode, Vitest, React Testing Library, and Playwright.
- [ ] Add application shell, sidebar, header, loading states, empty states, and error boundary.
- [ ] Implement one typed gateway API client.
- [ ] Add environment configuration without exposing server secrets.
- [ ] Add interview authentication using an in-memory API key or secure server session.
- [ ] Add Content Security Policy and standard browser security headers.
- [ ] Add frontend commands to the root `Makefile`.

### Acceptance criteria

- Frontend starts locally and builds successfully.
- Linting, type checking, unit tests, and build pass.
- No credentials are written to local storage or session storage.
- API errors display safe messages and request IDs.
- Browser telemetry does not collect prompts or responses.

---

## 18. Phase 17 — Secure Chat Workspace and Privacy Inspector

### Tasks

- [ ] Implement `/chat`.
- [ ] Add provider, model, and active-policy display.
- [ ] Implement conversation panel and prompt composer.
- [ ] Invoke `POST /v1/chat`.
- [ ] Render restored assistant output safely.
- [ ] Implement Privacy Inspector stages.
- [ ] Display entity counts, types, actions, policy version, and latency.
- [ ] Add clear-session action.
- [ ] Add synthetic prompt examples.
- [ ] Add blocked, rate-limited, provider-timeout, and vault-failure states.
- [ ] Prevent duplicate submission.
- [ ] Do not automatically retry chat requests.

### Acceptance criteria

- A synthetic prompt containing a name and email produces a restored response.
- The UI explains that the provider received protected placeholders.
- No mapping values or complete tokens are visible.
- Policy blocks are clearly distinguished from technical errors.
- Chat content is not placed in URLs, analytics, console logs, or browser storage.
- End-to-end tests cover the complete chat demonstration.

---

## 19. Phase 18 — Security and Operations Console

### Tasks

- [ ] Implement `/dashboard`.
- [ ] Implement metric cards and charts.
- [ ] Implement `/audit` and audit detail.
- [ ] Implement `/sessions` and session detail when supporting endpoints exist.
- [ ] Implement `/policies` in view-only mode first.
- [ ] Implement `/providers`.
- [ ] Implement `/health`.
- [ ] Add safe filtering and pagination.
- [ ] Add empty, loading, error, and unauthorized states.
- [ ] Ensure tables never display raw prompt or response fields.
- [ ] Add accessible chart summaries.

### Supporting backend endpoints

```text
GET /v1/dashboard/summary
GET /v1/audit
GET /v1/audit/{request_id}
GET /v1/sessions
GET /v1/sessions/{session_id}
GET /v1/policies
GET /v1/providers
GET /health/ready
```

### Acceptance criteria

- Dashboard renders from API data or documented mock mode.
- Audit and session pages contain metadata only.
- Health does not reveal internal hosts or secrets.
- Unauthorized roles cannot access administrator views.
- Charts use bounded, aggregated data.

---

## 20. Phase 19 — Policy Manager and Architecture Experience

### Tasks

- [ ] Implement policy detail and version history.
- [ ] Implement entity-action table.
- [ ] Implement JSON preview and validation.
- [ ] Save edits as a new version.
- [ ] Add explicit confirmation for weaker controls.
- [ ] Implement `/architecture`.
- [ ] Present data flow, trust boundaries, token lifecycle, and fail-closed behavior.
- [ ] Summarize selected ADRs.
- [ ] Implement `/about` with project purpose and limitations.

### Acceptance criteria

- Existing policy versions remain immutable.
- Invalid policies cannot be submitted.
- Architecture page explains the project without exposing secrets.
- The page distinguishes reversible tokenization from redaction.
- Known limitations are presented honestly.

---

## 21. Phase 20 — Interview Demo Hardening

### Tasks

- [ ] Add local mock provider mode.
- [ ] Add deterministic synthetic demo data.
- [ ] Add one-command startup for frontend, gateway, Redis, PostgreSQL, and mock provider.
- [ ] Add demo user and analyst credentials with minimal permissions.
- [ ] Add reset and seed scripts.
- [ ] Add graceful offline states.
- [ ] Add screenshots to README.
- [ ] Add `docs/demo-script.md`.
- [ ] Add `docs/interview-talk-track.md`.
- [ ] Run accessibility and responsive checks.
- [ ] Run the complete demo repeatedly from a clean environment.

### Acceptance criteria

- A reviewer can run the project without a paid LLM key.
- The main demo completes in under ten minutes.
- All displayed data is synthetic.
- No destructive administrator action is available to demo credentials.
- README provides exact setup and demo instructions.

---


## 22. Phase 21 — Test Strategy

### Unit tests

Cover:

- policy resolution
- overlap resolution
- normalization
- token generation
- parser
- encryption
- error mapping
- authentication
- repository tenant filters

### Integration tests

Use disposable PostgreSQL and Redis.

Cover:

- complete secure request flow
- TTL expiration
- concurrent token creation
- migrations
- session deletion
- dependency outages
- audit persistence

### Privacy regression tests

Search all outputs for synthetic canary values such as:

```text
SENSITIVE_CANARY_EMAIL_7f91@example.test
SENSITIVE_CANARY_SSN_123-45-6789
SENSITIVE_CANARY_NAME_Avery Example
```

Ensure canaries never appear in:

- logs
- traces
- metrics
- audit table
- mocked provider payload
- exception response

### Security tests

- Header injection.
- Oversized payload.
- Unicode confusables.
- Malformed token grammar.
- Cross-tenant access.
- Cross-session access.
- Ciphertext tampering.
- Invalid API keys.
- Rate-limit bypass attempt.
- Arbitrary provider alias.
- Prompt asking to reveal mappings.
- Provider output containing fabricated tokens.

### Property-based tests

- Random Unicode text and spans.
- Non-overlapping replacement invariants.
- Encrypt/decrypt round trip.
- Parser never restores malformed tokens.
- Different session produces different tokens.

### Coverage target

- 90% overall line coverage.
- 100% branch coverage for token parser, encryption envelope, tenant/session authorization, and policy block logic where practical.
- Coverage is not a substitute for privacy assertions.

---

## 23. Phase 22 — Performance Tests

### Scenarios

1. 4 KB text, no entities.
2. 4 KB text, 20 entities.
3. 16 KB text, 100 entities.
4. Concurrent repeated entity creation.
5. Redis latency injection.
6. Provider latency excluded and included.

### Report

Record:

- p50, p95, p99 gateway overhead.
- detection latency.
- vault latency.
- restoration latency.
- memory per worker.
- throughput by worker count.
- error rate.

### Acceptance criteria

- No unbounded memory growth.
- p95 gateway overhead target from architecture is evaluated.
- Results are documented even when target is not met.
- Performance optimization must not weaken privacy controls.

---

## 24. Error Codes

Implement at least:

```text
AUTHENTICATION_REQUIRED
AUTHENTICATION_FAILED
AUTHORIZATION_FAILED
RATE_LIMIT_EXCEEDED
REQUEST_TOO_LARGE
INVALID_REQUEST
UNSUPPORTED_LANGUAGE
POLICY_NOT_FOUND
POLICY_VIOLATION
ENTITY_LIMIT_EXCEEDED
PRIVACY_DETECTOR_UNAVAILABLE
VAULT_UNAVAILABLE
VAULT_ENCRYPTION_FAILED
PROVIDER_NOT_ALLOWED
MODEL_NOT_ALLOWED
PROVIDER_TIMEOUT
PROVIDER_UNAVAILABLE
PROVIDER_RESPONSE_INVALID
RESTORATION_FAILED
AUDIT_UNAVAILABLE
INTERNAL_ERROR
```

Each code maps to one HTTP status and one safe public message.

---

## 25. API Example

```bash
curl --request POST \
  --url http://localhost:8000/v1/chat \
  --header "Authorization: Bearer ${SECURE_GATEWAY_API_KEY}" \
  --header "Content-Type: application/json" \
  --data '{
    "provider": "mock",
    "model": "general-chat",
    "messages": [
      {
        "role": "user",
        "content": "Please confirm follow-up with Avery Example at avery@example.test."
      }
    ]
  }'
```

Expected provider-bound prompt in test:

```text
Please confirm follow-up with ⟦SGW:PERSON:<TOKEN_ID>⟧ at ⟦SGW:EMAIL_ADDRESS:<TOKEN_ID>⟧.
```

Expected authorized client response:

```text
Follow-up can be sent to Avery Example at avery@example.test.
```

---

## 26. Manual Security Verification Checklist

Before release:

- [ ] Inspect Redis and confirm no plaintext canaries.
- [ ] Inspect PostgreSQL and confirm no plaintext canaries.
- [ ] Inspect application logs and confirm no plaintext canaries.
- [ ] Inspect Prometheus exposition and confirm no identifiers.
- [ ] Inspect mocked provider requests and confirm no originals.
- [ ] Attempt cross-tenant restoration.
- [ ] Attempt cross-session restoration.
- [ ] Tamper with ciphertext.
- [ ] Expire session and attempt restoration.
- [ ] Fabricate valid-looking tokens.
- [ ] Disable Redis and confirm provider is not invoked.
- [ ] Disable detector and confirm provider is not invoked.
- [ ] Trigger provider timeout and inspect error response.
- [ ] Run dependency and secret scanners.
- [ ] Review CORS and network exposure.
- [ ] Confirm production does not use development keys.

---

## 27. Release Criteria

Version 1 may be tagged only when:

- All mandatory phase checklists are complete.
- CI passes.
- Privacy regression test passes.
- No critical or high dependency vulnerabilities remain without documented acceptance.
- Threat model is reviewed.
- Docker Compose demo works.
- OpenAPI schema matches implementation.
- Provider calls are mocked in automated tests.
- Logs and audit data contain no synthetic canaries.
- Cross-tenant and cross-session tests pass.
- README includes operational warnings and known limitations.

---

## 28. Suggested Implementation Order by Pull Request

1. `bootstrap-and-ci`
2. `config-lifecycle-safe-logging`
3. `database-migrations-repositories`
4. `api-key-auth-and-rate-limit`
5. `policy-engine`
6. `detection-engine`
7. `tokenization-domain`
8. `encrypted-redis-vault`
9. `secure-pipeline`
10. `openai-provider-adapter`
11. `restoration-output-policy`
12. `public-api`
13. `audit-and-privacy-regression`
14. `metrics-health-observability`
15. `frontend-bootstrap`
16. `secure-chat-privacy-inspector`
17. `security-operations-console`
18. `policy-and-architecture-pages`
19. `docker-compose-demo-hardening`
20. `privacy-e2e-performance-release-docs`

Each pull request must be independently testable and must not introduce a temporary insecure bypass.

---

## 29. Claude Code Completion Prompt

Use this prompt from the repository root:

```text
Read architecture.md and implementation.md in full.

Implement the Secure AI Gateway one phase at a time, beginning with the first
unchecked phase. Follow all security invariants exactly.

Rules:
- Never send raw detected sensitive data to a provider.
- Never log request bodies, response bodies, mappings, credentials, or full tokens.
- Fail closed when detection, policy, tokenization, vault, or restoration fails.
- Keep all provider calls behind the protected-request interface.
- Use mocked provider transports in tests.
- Add tests for every acceptance criterion.
- Run formatting, linting, type checking, unit tests, integration tests, and
  privacy tests after each phase.
- Do not continue to the next phase until the current phase passes.
- Update this checklist as work is completed.
- Do not implement streaming, Kubernetes, extra providers, file processing, or features outside the documented interview UI scope in v1.
- Implement frontend phases only after the backend privacy pipeline and its tests are complete.
- Read `docs/frontend-architecture.md`, `docs/ui-wireframes.md`, `docs/demo-script.md`, and `docs/interview-talk-track.md` before implementing the frontend.
```
