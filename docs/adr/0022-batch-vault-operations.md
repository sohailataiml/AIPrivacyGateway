# ADR-0022: Use Batch Vault Operations

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Every protected entity costs a vault interaction. A prompt with forty detected
entities is forty mappings to write; a response carrying forty tokens is forty
mappings to read.

The read path was built this way from the start: `TokenVault.resolve_many`
takes a set of tokens and returns their originals in one round trip, and
restoration performs a single-pass substitution over the result.

The write path was not. The tokenizer walks the detected spans in reverse
positional order and awaits `get_or_create` once per span, so latency scales
linearly with entity count and is dominated by network round trips rather than
by any work the gateway does. Under the benchmark targets in
[performance.md](../performance.md) — detection, protection, and vault writes
inside two seconds for a 2,000-word document — a per-token round trip is the
first thing to exhaust the budget, and a document-sized input makes it
structural rather than marginal.

The per-token call also serialises work that has no ordering requirement
between entities. Token *substitution* must respect positional order; token
*minting* need not.

## Decision

Use batch mapping writes and batch token resolution. **Never one network round
trip per token.**

`TokenVault` exposes a batch write alongside the existing batch read. The
tokenizer mints every mapping for a request in one vault interaction, then
performs substitution positionally over the returned mapping.

## Consequences

### Positive

- Vault latency becomes a function of request count, not entity count.
- The 2,000-word document target in [performance.md](../performance.md) becomes
  reachable; per-token round trips make it arithmetically impossible.
- Fewer, larger interactions are easier to bound, observe, and reason about
  than a variable-length sequence of small ones.
- The write path gains the shape the read path already has, so both seams read
  the same way.

### Negative

- A batch operation is harder to make atomic than a single one, and the
  get-or-create semantics under concurrency must survive the change intact.
- Partial failure needs an explicit answer: a batch that half-succeeds must not
  leave the caller with a token whose mapping was never stored.
- Large batches must be bounded so a single request cannot monopolise the vault
  or exceed the store's limits.

## Alternatives Considered

- **Concurrent per-token calls (`asyncio.gather`).** Reduces wall-clock latency
  without reducing round trips, multiplies connection pressure, and makes the
  atomic get-or-create race window wider rather than narrower. Rejected.
- **Client-side caching of recent mappings.** Adds a plaintext cache of
  Restricted values in process memory — precisely what the encrypted vault
  exists to avoid. Rejected.
- **Accepting per-token writes and relaxing the performance target.** The target
  exists because document processing (ADR-0020) makes forty-entity inputs
  ordinary rather than exceptional. Rejected.

## Implementation Constraints

- One vault interaction per request for writes, and one for reads. The count of
  round trips must not vary with the number of entities.
- The batch write preserves get-or-create semantics per entry: repeated calls
  with the same normalized fingerprint, in the same tenant and session, return
  the same token — including when two requests race.
- The batch is atomic in the sense that matters to the caller: a returned token
  always has a stored, readable mapping. No partial result is returned as
  success.
- Every key written carries a TTL, including index and metadata keys. A batch
  must not create a key that outlives the session.
- Failure is closed, per ADR-0008. A batch that cannot be completed raises
  rather than returning the subset that succeeded.
- Batch size is bounded by the request-wide entity budget already enforced in
  the pipeline; no unbounded batch reaches the vault.
- Duplicate fingerprints within one request collapse to one entry before the
  vault is called, so a repeated value costs nothing extra.
- The batch write is part of the `TokenVault` Protocol, so every implementation
  — Redis and fakes alike — and the conformance tests move together.
