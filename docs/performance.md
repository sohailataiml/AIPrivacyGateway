# Performance Requirements and Benchmark Plan

**This document owns the performance targets.** Runtime alerting — what pages a
human when a live deployment misbehaves — is owned by
[observability.md](observability.md) §4. The two are related but distinct: a
target is a property the build must demonstrate on demand, an alert threshold is
a judgement about live traffic. Where an alert threshold is a latency number, it
should be derived from the measurements this plan produces, not invented
alongside them.

---

## 1. Targets

| Benchmark | Target |
|---|---:|
| Full 2,000-word pipeline with mock provider | < 15 s |
| Detection + protection + vault writes | < 2 s |
| Effective batch vault lookup per token | < 5 ms |
| Restore 500-token response | < 500 ms |
| Leakage regression | 100/100 pass |

Report **p50, p95, and p99** for every latency target. A mean hides exactly the
behaviour worth knowing about.

Two of these are not really latency targets:

- **"Effective … per token"** is a whole-batch measurement divided by token
  count. It is stated per token to make the batching requirement of ADR-0022
  measurable: with one round trip per token the number is a network round trip
  and cannot be met; with batching it is arithmetic on a single interaction.
- **Leakage regression** is a correctness gate that happens to live in the
  performance suite, because the batching and concurrency work most likely to
  break it is measured here. 100/100 or the build fails.

---

## 2. Method

- **Deterministic mock provider in CI** (ADR-0016). A benchmark that calls a real
  provider measures the provider's queue, not this gateway.
- **Benchmark extraction separately.** Document extraction is CPU-bound and
  varies by file type and size; folding it into the pipeline number produces a
  figure that describes the corpus rather than the code.
- **Measure the gateway's own overhead separately from provider latency.** The
  gateway controls one of these. `sgw_pipeline_stage_duration_seconds` and
  `sgw_provider_duration_seconds` already separate them.
- **Report the machine.** A number without the hardware and the concurrency
  level it was taken at is not reproducible.

## 3. Implementation requirements these targets imply

- Batch Redis operations — never one round trip per token (ADR-0022).
- One-pass token parsing and single-pass substitution on restoration.
- Bounded concurrency, so a load test degrades predictably rather than
  collapsing.

---

## 4. Status

**Not yet measured.** Nothing in this table has been run against the stack; the
system has served hand-driven requests only and has never seen concurrency.
Until this suite exists, every latency threshold in
[observability.md](observability.md) §4 is a reasoned starting point rather than
a measured one, and both documents say so.

The order of work is: make the batch-vault change (ADR-0022), then measure, then
replace the provisional alert thresholds with values derived from the results.
