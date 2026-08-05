# Observability

What the gateway publishes, what it deliberately does not, and what to alert on.

---

## 1. The rule every instrument obeys

**A label value must come from a set that is closed at import time.**

A Prometheus registry is a process-lifetime data structure with no eviction. A
label drawn from a request is therefore not an ordinary leak but a permanent
one, and enough distinct values is an outage — the scrape slows, then fails, and
the monitoring goes dark at the moment it is needed. Two consequences:

- **Nothing identifying is ever a label.** No tenant id, api key id, session id,
  request id, token, token id, or detected value. Not as a label, not as a
  metric name, not anywhere in the exposition payload.
- **Caller-controlled strings are folded onto closed sets before use.** The HTTP
  route label is Starlette's *route template*, so `/v1/sessions/{session_id}` is
  one series no matter how many session ids are deleted; anything matching no
  route collapses onto `unmatched`. The method is folded onto the seven standard
  verbs plus `other`. Entity types are folded onto the detector's supported set
  plus `OTHER`.

Every `metrics.py` module in `app/` enforces this in code: the recorder
functions validate their arguments against the closed set and raise on anything
else, so a dynamic label fails a test rather than growing the registry in
production. `tests/unit/test_observability.py` tests each recorder for what it
refuses; `tests/unit/test_api_v1.py::TestMetricsExposure` drives a request
carrying an email, a name, a phone number, an SSN, and an IP through the whole
stack and then searches the entire scrape payload for any of it.

**Two things are deliberately absent from the label set** where the architecture
document suggested them:

| Suggested | Why it is not a label |
| --- | --- |
| `model` on the provider metrics | The model alias reaches the provider stage caller-supplied and is only validated inside the adapter's own catalog. Labelling by it would let a caller mint series. The model of record for a request is in its audit row. |
| `entity_type` on vault metrics | The vault receives the entity type from its caller and cannot bound it. The tokenizer can, and does — that is where `sgw_entities_detected_total` lives. |

---

## 2. The metrics

### HTTP — `app/observability/metrics.py`

| Metric | Type | Labels |
| --- | --- | --- |
| `sgw_http_requests_total` | counter | `method`, `route`, `status` |
| `sgw_http_request_duration_seconds` | histogram | `method`, `route` |
| `sgw_active_requests` | gauge | — |

Recorded by `MetricsMiddleware`, which sits outside the body-size limit so a
rejected oversized body is still counted, and inside the request id so a metric
and a log line describe the same span.

### Request path — `app/pipeline/metrics.py`

| Metric | Type | Labels |
| --- | --- | --- |
| `sgw_pipeline_stage_duration_seconds` | histogram | `stage` |
| `sgw_pipeline_stage_total` | counter | `stage`, `outcome` |
| `sgw_policy_blocks_total` | counter | `reason` |
| `sgw_provider_requests_total` | counter | `provider`, `result` |
| `sgw_provider_duration_seconds` | histogram | `provider` |
| `sgw_restoration_unknown_tokens_total` | counter | — |

`stage` is a `PipelineStage` member: `policy`, `detection`, `tokenization`,
`provider`, `restoration`, `audit`. Detection and tokenization are observed once
per message; every other stage once per request. `outcome` separates
`deadline_exceeded` from `failed`, because "the detector is down" and "we ran
out of time" have different remedies.

`sgw_policy_blocks_total` counts refusals only — a dependency outage is not a
policy block, and folding the two together would make a Redis incident look like
a policy change. The reason is derived from the error *type* at a single call
site, so no raise site can invent a label.

### Privacy actions — `app/tokenization/metrics.py`

| Metric | Type | Labels |
| --- | --- | --- |
| `sgw_entities_detected_total` | counter | `entity_type`, `action` |

Recorded before the block check, so a span that policy blocks is counted rather
than vanishing along with the request it stopped.

### Subsystems

Defined next to the code that owns them and exported through the same registry:
`app/vault/metrics.py` (operation latency and outcomes, created-versus-reused
records, token lookups), `app/auth/metrics.py` (authentication, authorization,
rate-limit decisions, `last_used_at` writes), `app/audit/metrics.py` (event
outcomes, failure reasons, queue depth and capacity, write latency).

---

## 3. `GET /metrics`

Guarded by a dedicated bearer token, `METRICS_TOKEN`, rather than by the API-key
machinery every other route uses. The reason is availability: `require_scope`
reaches PostgreSQL to verify a key, so using it here would blank the dashboards
at exactly the moment the database goes down — and the metrics explaining *why*
are already in memory, waiting to be read. The check is a constant-time
comparison and touches nothing.

| Configuration | Behaviour |
| --- | --- |
| `METRICS_ENABLED=false` | The route does not exist. Absent, not forbidden: a 401 still confirms there are metrics here worth asking for. |
| `METRICS_TOKEN` unset | The endpoint is open. Convenient locally; **impossible in production** — `Settings` refuses to build. |
| `METRICS_TOKEN` set | `Authorization: Bearer <token>` required. Absent and incorrect tokens get the identical 401, so the endpoint is not an oracle. |

In production the token must also be at least 32 characters and not a known
development placeholder.

The payload carries no identifying value, but request rates, error rates,
provider failures, and audit queue depth together describe the health and shape
of the deployment. That is reconnaissance worth denying to an anonymous reader,
which is what the token is for. Prefer `authorization.credentials_file` in a
real Prometheus configuration over inlining the token.

---

## 4. Recommended alerts

**This section owns runtime alerting only.** Benchmark targets — what the build
must demonstrate on demand — belong to [performance.md](performance.md) and are
not restated here. An alert threshold is a judgement about live traffic; a
target is a property of the system. Where an alert below is a latency number, it
should be derived from the measurements `performance.md` produces.

Thresholds below are starting points for a single instance, and none of them has
been measured — `performance.md` §4 records that the benchmark suite has not been
run. Tune them against observed behaviour before trusting them to page anyone.

### Page

| Alert | Expression sketch | Why |
| --- | --- | --- |
| **Elevated 5xx** | `rate(sgw_http_requests_total{status=~"5.."}[5m]) / rate(sgw_http_requests_total[5m]) > 0.05` for 5m | The gateway is failing requests. |
| **Detector unavailable** | `rate(sgw_pipeline_stage_total{stage="detection",outcome!="success"}[5m]) > 0` for 5m | Detection fails closed, so this is a total outage of `/v1/chat`, not degraded service. |
| **Vault unavailable** | `rate(sgw_vault_operations_total{outcome="unavailable"}[5m]) > 0` for 5m | No mappings can be written; no request can reach a provider. |
| **Audit queue saturating** | `sgw_audit_queue_depth / sgw_audit_queue_capacity > 0.8` for 5m | With `AUDIT_FAIL_CLOSED=true` a full queue starts failing requests. This is the warning before that. |
| **Audit dropping events** | `rate(sgw_audit_failures_total{reason="queue_full"}[5m]) > 0` | Compliance records are being lost. |
| **Readiness flapping** | `/health/ready` returning 503 | Redis or PostgreSQL is unreachable. |

### Warn

| Alert | Expression sketch | Why |
| --- | --- | --- |
| **Unknown output tokens** | `rate(sgw_restoration_unknown_tokens_total[15m]) > 0` sustained | The provider is echoing tokens no mapping resolves — usually session TTLs expiring inside a live conversation, occasionally a model inventing token-shaped text. |
| **Provider timeouts** | `rate(sgw_provider_requests_total{result="timeout"}[5m])` above baseline | Upstream degradation. Distinguish from `result="cancelled"`, which means *the gateway's own deadline* fired. |
| **Rate-limit spike** | `rate(sgw_rate_limit_decisions_total{outcome="throttled"}[5m])` above baseline | A tenant is over budget, or a key has leaked. |
| **Rate limiter failing closed** | `rate(sgw_rate_limit_decisions_total{outcome="backend_error_failed_closed"}[5m]) > 0` | Redis is unreachable and callers are being denied. |
| **Authentication failure spike** | `rate(sgw_auth_attempts_total{outcome="invalid_credential"}[5m])` above baseline | Credential stuffing, or a rotation that broke a client. |
| **Detection latency regression** | `histogram_quantile(0.95, rate(sgw_pipeline_stage_duration_seconds_bucket{stage="detection"}[10m])) > 0.25` | The gateway's overhead budget is being spent in one stage. |
| **Policy blocks spike** | `rate(sgw_policy_blocks_total[15m])` above baseline | Either a policy edit is refusing legitimate traffic, or a client started sending data it should not. Both want a human. |
| **Saturation** | `sgw_active_requests` near the provider concurrency bound | Requests are queueing on the semaphore. |
| **Redis memory pressure** | `redis_memory_used_bytes / redis_memory_max_bytes > 0.85` | The vault is `volatile-ttl`; under pressure it evicts mappings early, which surfaces as unknown output tokens. |

### Notes on interpreting these

- **`sgw_policy_blocks_total` going to zero is also a signal.** If a tenant's
  traffic normally trips the block rule and stops doing so, the policy may have
  been edited rather than the traffic having changed.
- **`sgw_entities_detected_total` dropping to zero while traffic continues** is
  the shape of a detection regression: requests succeed, nothing is tokenized,
  and raw values reach the provider. It is the single most valuable series here
  and deserves an alert tuned to the deployment's baseline.

---

## 5. Logs and traces

Structured JSON logs in production, key-value in development, with the request
id bound as context. The allowlist in `app/observability/logging.py` decides
what may be emitted; message content, original values, mappings, tokens, and
credentials are not on it.

Third-party debug logging is a recurring leak class and is handled explicitly:
`presidio-analyzer` logs analyzed text at `DEBUG`, and the OpenAI SDK and httpx
log full request bodies at `DEBUG`. Both are raised to `WARNING` at import, and
both fixes have a test that fails if the silencing is removed. **Any new
dependency that touches message content needs the same treatment.**

**Tracing is not implemented.** `OTEL_EXPORTER_OTLP_ENDPOINT` exists in
`Settings` and nothing reads it; there is no OpenTelemetry dependency and no
instrumentation. It was optional in the phase plan and remains the one Phase 13
task not done. When it is added, the constraint is the same one the label rule
expresses: span attributes may carry component names, timing, and result codes,
and prompt text, original values, and mappings are forbidden.
