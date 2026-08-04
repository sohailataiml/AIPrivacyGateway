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

- Web dashboard.
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

- [ ] Create directory structure from `architecture.md`.
- [ ] Initialize `pyproject.toml`.
- [ ] Configure Ruff formatting and linting.
- [ ] Configure mypy in strict or near-strict mode.
- [ ] Configure pytest and coverage.
- [ ] Add `.gitignore`.
- [ ] Add `.env.example` with variable names and safe placeholders.
- [ ] Add `Makefile`.
- [ ] Add pre-commit configuration.
- [ ] Add CI workflow for lint, type check, tests, dependency audit, and secret scan.
- [ ] Add `README.md` with local setup instructions.
- [ ] Add a minimal `app/main.py`.

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

- [ ] Implement typed settings in `app/config/settings.py`.
- [ ] Add environment profiles: `local`, `test`, `production`.
- [ ] Validate required production secrets.
- [ ] Configure FastAPI lifespan.
- [ ] Initialize Redis and PostgreSQL clients during startup.
- [ ] Close resources during shutdown.
- [ ] Add request ID middleware.
- [ ] Add safe structured logging.
- [ ] Add global exception handlers.
- [ ] Add CORS disabled by default.
- [ ] Add body-size enforcement.

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

- [ ] Configure async SQLAlchemy engine and sessions.
- [ ] Configure Alembic.
- [ ] Create migrations for tenants, API keys, policies, provider configs, and audit events.
- [ ] Implement repository interfaces.
- [ ] Add transaction helper.
- [ ] Seed one local tenant and default policy through an idempotent script.
- [ ] Store only provider secret references, never provider secrets.

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

- [ ] Parse `Authorization: Bearer <api-key>`.
- [ ] Resolve API key by prefix.
- [ ] Verify its hash safely.
- [ ] Reject expired, disabled, or unknown keys.
- [ ] Construct immutable `Principal`.
- [ ] Implement scope dependency.
- [ ] Update `last_used_at` asynchronously or with bounded frequency.
- [ ] Implement Redis-backed fixed-window or sliding-window rate limiting.
- [ ] Rate limit by tenant and API key.
- [ ] Add authentication and rate-limit metrics.

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

- [ ] Define policy schema.
- [ ] Implement default policy.
- [ ] Implement tenant policy repository.
- [ ] Resolve active policy snapshot per request.
- [ ] Validate entity actions and thresholds.
- [ ] Validate provider and model allowlists.
- [ ] Add policy version to request context and audit metadata.
- [ ] Cache policy documents briefly without caching secrets.
- [ ] Add policy-validation command.

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
    "PHONE_NUMBER": {"action": "tokenize", "min_score": 0.65},
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

- [ ] Define detector interface and domain models.
- [ ] Integrate Presidio analyzer.
- [ ] Configure spaCy model through setup documentation.
- [ ] Add custom regex recognizers for:
  - [ ] API keys or bearer tokens.
  - [ ] Medical record number sample format.
  - [ ] Health plan identifier sample format.
  - [ ] Enterprise account number sample format.
- [ ] Add allowlist support.
- [ ] Add confidence thresholds.
- [ ] Implement deterministic overlap resolution.
- [ ] Add language parameter with English enabled.
- [ ] Add maximum-entity guard.
- [ ] Record recognizer name only in diagnostic mode.

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

- [ ] Define exact token grammar.
- [ ] Implement cryptographically random token IDs.
- [ ] Implement entity-specific normalization.
- [ ] Implement HMAC fingerprinting.
- [ ] Implement right-to-left replacement.
- [ ] Implement action handlers for allow, tokenize, redact, pseudonymize, and block.
- [ ] Return a protected type that cannot be confused with raw input.
- [ ] Add repeated-value token reuse within a session.
- [ ] Enforce maximum entity count.
- [ ] Add property-based tests for offset safety.

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

- [ ] Define vault interface.
- [ ] Implement AES-256-GCM envelope encryption.
- [ ] Load active key and key ring through settings.
- [ ] Include associated data.
- [ ] Implement token record storage.
- [ ] Implement fingerprint-to-token index.
- [ ] Implement atomic create-or-reuse operation using Lua or transaction.
- [ ] Apply TTL to all keys.
- [ ] Implement batch retrieval.
- [ ] Implement session deletion.
- [ ] Implement key-rotation-compatible decryption.
- [ ] Add vault latency and result metrics.

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

- [ ] Implement pipeline service.
- [ ] Process system, user, and assistant message content.
- [ ] Resolve one session ID.
- [ ] Apply policy and detection.
- [ ] Persist mappings before provider invocation.
- [ ] Produce `ProtectedChatRequest`.
- [ ] Add privacy metadata counters.
- [ ] Add pipeline timeout.
- [ ] Add bounded concurrency for provider calls.
- [ ] Add fail-closed errors.

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

- [ ] Define provider registry.
- [ ] Implement `OpenAIProvider`.
- [ ] Map internal model alias to provider model ID.
- [ ] Use the current official OpenAI text generation interface supported by the installed SDK.
- [ ] Configure timeouts.
- [ ] Configure bounded retry for transient network and selected `429` or `5xx` responses.
- [ ] Disable storage where supported and required by policy.
- [ ] Map provider errors into domain errors.
- [ ] Capture usage metadata.
- [ ] Add HTTP mocking with `respx` or SDK transport fakes.
- [ ] Ensure provider client never logs request content.

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

- [ ] Implement strict token parser.
- [ ] Buffer and parse synchronous response.
- [ ] Batch vault resolution.
- [ ] Restore only complete exact tokens.
- [ ] Preserve unknown tokens by default.
- [ ] Add unknown-token count.
- [ ] Enforce output-size limit.
- [ ] Add optional output scan.
- [ ] Reject malformed provider payloads.
- [ ] Prevent recursive or repeated restoration errors.

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

- [ ] `POST /v1/chat`
- [ ] `POST /v1/detect`
- [ ] `DELETE /v1/sessions/{session_id}`
- [ ] `GET /health/live`
- [ ] `GET /health/ready`
- [ ] `GET /metrics`

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

- [ ] Implement audit event model and repository.
- [ ] Add bounded asynchronous queue.
- [ ] Record request outcome and privacy counts.
- [ ] HMAC prompt and response for correlation.
- [ ] Store policy version.
- [ ] Add audit failure metric.
- [ ] Add configurable fail-open or fail-closed audit behavior; production default should be explicit.
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

- [ ] Add Prometheus metrics from architecture specification.
- [ ] Add safe structured logs.
- [ ] Add optional OpenTelemetry tracing.
- [ ] Add readiness checks.
- [ ] Add dependency status without exposing credentials or hosts.
- [ ] Add sample Grafana dashboard JSON only if time permits.
- [ ] Add alert recommendations to README.

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

- [ ] Create multi-stage Dockerfile.
- [ ] Run as non-root.
- [ ] Add health check.
- [ ] Use read-only filesystem where practical.
- [ ] Drop Linux capabilities.
- [ ] Mount only required writable temporary directories.
- [ ] Create Docker Compose configuration.
- [ ] Add migration startup command or explicit documented migration step.
- [ ] Add seed script.
- [ ] Add local mock-provider option for demos.
- [ ] Ensure local default does not accidentally call a paid provider.

### Acceptance criteria

- `docker compose up --build` starts the stack.
- Health endpoint becomes ready.
- Demo request works against mock provider.
- Container runs as non-root.
- Image does not include `.env`, tests containing secrets, or build caches.

---

## 20. Phase 15 — Test Strategy

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

## 21. Phase 16 — Performance Tests

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

## 22. Error Codes

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

## 23. API Example

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

## 24. Manual Security Verification Checklist

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

## 25. Release Criteria

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

## 26. Suggested Implementation Order by Pull Request

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
15. `docker-compose-hardening`
16. `performance-and-release-docs`

Each pull request must be independently testable and must not introduce a temporary insecure bypass.

---

## 27. Claude Code Completion Prompt

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
- Do not implement streaming, dashboards, Kubernetes, or extra providers in v1.
```
