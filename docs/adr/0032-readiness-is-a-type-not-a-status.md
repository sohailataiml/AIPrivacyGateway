# ADR-0032: Readiness for Protection Is a Type, Not a Document Status

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

The document pipeline ends detection with a document that is *ready to be
protected*: its sensitive spans are located, deduplicated, and carry a policy
decision. The next phase — tokenization, vault writes, the outbound payload —
needs to know that work happened and that it can be trusted.

The obvious way to express "ready" is a lifecycle status. `DocumentStatus`
already exists, the `documents` table already has the column, and adding an
`analyzed` member is a one-line change plus a migration.

Two things make it the wrong answer.

**Nothing is persisted.** ADR-0030 decided that extracted text is never written
down, and spans are a description of that text — an offset plus the stored
ciphertext is a map of where a document's sensitive values are. The analysis
exists for the life of one call. A persisted status would therefore describe
state that no longer exists by the time anyone reads it, and the next request
would have to extract and detect again regardless of what the column said.

`docs/document-processing.md` already states the rule this violates: "a status
the system cannot reach is a lie told to whoever polls for it." A status the
system *can* set but which describes nothing is the same lie with extra steps.

**The project already has a better mechanism for exactly this.**
`app/domain/models.py` draws the boundary between `ChatRequest` and
`ProtectedChatRequest` and explains why: "Because the two are distinct types
with no inheritance between them, sending unprocessed text to a provider is a
type error rather than a review miss."

## Decision

Readiness is carried by **`AnalyzedDocument`**, whose construction is the
checkpoint. No `DocumentStatus` member is added, and **Phase 3 writes no
migration**.

Construction refuses anything the protection phase would otherwise have to
re-validate:

| Invariant | Why the next phase depends on it |
|---|---|
| Spans are ordered by offset and none overlap | Protection splices right to left; two overlapping spans mean one splice corrupts the other's offsets |
| Every span lies inside the text buffer | A span past the end replaces characters that do not exist |
| No span carries `BLOCK` | A blocked value refuses the document; `LabeledSpan` cannot represent one |
| Every span names at least one page and one segment | A span that cannot say where it came from cannot be traced in an audit record |

So "I hold an `AnalyzedDocument`" means the policy has been applied, nothing in
it was blocked, and the spans are safe to splice — without the next phase
checking any of it.

**Counts are derived, not stored.** `counts_by_action()` and
`counts_by_entity_type()` are computed from `spans` on each call, for the same
reason a page owns no text in ADR-0029: a stored summary can disagree with what
it summarises, and a derived one cannot.

## Consequences

### Positive

- **The guarantee is checked by the compiler and the constructor**, not by a
  reviewer noticing a missing call.
- **No migration, no schema change, no rollback risk.** The `documents` table is
  untouched.
- **No misleading state.** Nothing polls a status that would be stale the moment
  the request ended.
- **ADR-0030 stays intact** rather than being quietly eroded by a column that
  implies persistence.
- **A clean document is representable.** Zero spans is a valid
  `AnalyzedDocument`, so "nothing sensitive found" is distinguishable from
  "detection failed" — the latter raises.

### Negative

- **No resumability and no caching.** Every pass re-extracts and re-detects.
  ADR-0030 already accepted this cost; this decision inherits it.
- **No externally visible progress.** A caller cannot poll a document to see
  whether it has been analyzed, because the answer is always "not right now".
  If a phase later needs asynchronous document processing, it needs durable
  state — and a superseding ADR, not a status member added quietly.
- **The type must be passed around.** It carries the `SegmentedDocument`, and
  therefore the text, so it is Restricted and cannot be logged, serialized, or
  returned. Both it and `LabeledSpan` hide their contents from `repr`.

## Alternatives Considered

- **Add `DocumentStatus.ANALYZED` with a migration.** The conventional answer,
  and it records a fact that stops being true when the request ends. Rejected.
- **Persist the spans (offsets and types, no values) and set a status.** Makes
  the status honest and creates a durable map of where each document's
  sensitive values are — with a retention obligation, a subject-access answer,
  and a new thing to encrypt. Strictly worse than re-detecting. Rejected; it
  would need to supersede ADR-0030 explicitly.
- **Return a plain tuple of spans.** Loses the invariants, and the protection
  phase would have to re-establish them or assume them. Assumption is what
  ADR-0029 calls the fail-open outcome that every count reports as a success.
  Rejected.
- **A boolean `is_ready` flag on an existing type.** A flag that can be set is a
  flag that can be set wrongly. Rejected.

## Implementation Constraints

- `AnalyzedDocument` and `LabeledSpan` are frozen, slotted dataclasses with a
  `__repr__` that reports counts only.
- `LabeledSpan` holds no text. Reading a span's value requires the buffer, which
  requires the `AnalyzedDocument`.
- The analyzer raises rather than returning an empty or partial result: a
  blocked entity raises `PolicyViolationError`, an over-budget document raises
  `EntityLimitExceededError`, and a detector that cannot run raises
  `DetectorUnavailableError`.
- If a future phase needs durable analysis state, it needs a superseding ADR —
  not a configuration flag and not a new enum member.

## As Built (Phase 3)

`app/documents/analysis/models.py`.

`tests/unit/test_document_analysis_spans.py::TestAnalyzedDocumentInvariants` and
`::TestLabeledSpanInvariants` assert each refusal individually, so every
invariant the table above claims has a test proving it is enforced rather than
documented. `tests/unit/test_document_analysis.py::TestNothingIsRetained`
asserts the object store is unchanged across an analysis, that the document row
count is unchanged, that no table named for spans or analysis exists, and that
`DocumentStatus` still has exactly three members.
