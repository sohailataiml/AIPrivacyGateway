# ADR-0033: Protect Documents With the Prompt Tokenizer, Not a Second One

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

Applying a document's labeled spans means two things the gateway already does:
splice replacements into text, and mint the vault mappings those replacements
stand for. `app/tokenization/tokenizer.py` does both for prompts.

It is tempting to write a document-shaped version. Documents have a different
budget, arrive with their actions already decided, and carry a
`SegmentedDocument` rather than a message — so a purpose-built protector would
be shorter and would read more naturally against `AnalyzedDocument`.

It would also be a second copy of the two pieces of code in this system where a
mistake is silent and unrecoverable:

- **The splice runs right to left**, because every offset indexes the *original*
  string. Going left to right shifts every later span by the difference between
  a value's length and its token's, so the protection lands progressively
  further from the value — and the output still looks like a protected document.
- **Mappings are minted in one call** (ADR-0022). A round trip per span is fine
  for a sentence and arithmetically fatal for a document.

A second implementation of either is a second place for them to drift, and the
drift would be invisible until a document went out with an original in it.

But reuse is not free either, because the tokenizer takes *spans and a policy*
and derives the actions itself. Three things have to line up or reuse becomes a
subtler version of the bug it avoids.

## Decision

Document protection **calls the prompt tokenizer**, unchanged.
`app/documents/protection.py` is orchestration plus the three things that have
to line up.

### 1. The policy is the one analysis used

`AnalyzedDocument` carries its `PolicySnapshot`, not a version number, and the
protector hands that snapshot to the tokenizer. Policy is cached for 30 seconds
and an operator can edit it at any moment, so a protector that resolved the
policy again could apply actions the labels never agreed to — both stages
correct in isolation, every count reporting success, and the wrong text sent.

Because the tokenizer re-derives actions from that snapshot, the derivation
reproduces the labels exactly. That is a property, not a hope, so it is checked
rather than assumed (below).

### 2. The entity budget is the document's

The tokenizer enforces `policy.max_entities`, which is the *per-request* ceiling
— 500 in the shipped default, sized for a prompt. Analysis has already enforced
`MAX_DOCUMENT_ENTITIES` against the same spans, so re-applying the prompt
ceiling would refuse documents that analysis accepted, at the very end of the
most expensive path in the system.

`_DocumentEntityBudget` is a read-through view of the snapshot that reports the
document ceiling and answers every other question from the snapshot itself. It
is a substitution, not a bypass: the ceiling it reports is a deployment setting
that has already been enforced against these exact spans.

### 3. The session belongs to the caller

`protect()` takes a `session_id`. The vault is session-scoped by design
(ADR-0003, ADR-0023) — a token minted in one session does not resolve in
another, and logout destroys them. A document's tokens are only useful in the
conversation that will quote them, so inventing a session here would mint
mappings nothing can resolve and nothing but a TTL will ever clean up.

### The guard that makes reuse safe

The tokenizer re-selects: it re-validates bounds, re-applies the policy's
confidence thresholds, and re-resolves overlaps with its own simpler rule
(`app/tokenization/selection.py`). On spans analysis has already made
non-overlapping and confident, all three are no-ops.

"Should be a no-op" is exactly the kind of claim that stops being true when one
of the two overlap rules is edited and the other is not. So the protector
compares what came back against what was labeled, and **refuses a result that
acted on a different number of spans**. A silently dropped span would otherwise
mean text with an original still in it and a summary calling the document
protected.

## Consequences

### Positive

- **One splice and one mint in the system.** A fix to either fixes both paths;
  neither can drift from the other.
- **Documents and prompts protect identically.** Same token grammar, same
  normalization, same fingerprint pepper, same vault, so a value tokenized in a
  document and quoted in a prompt collapses onto one token within a session.
- **The reuse is checked, not trusted.** The span-count guard turns a
  cross-module assumption into a runtime refusal.
- **`ProtectedDocument` is the provider checkpoint**, mirroring
  `ProtectedChatRequest`: it exists only where every mapping is durably in the
  vault, and it carries no mappings for anything downstream to leak.

### Negative

- **Protection re-derives what analysis already decided.** The work is trivial
  next to detection, and the duplication is deliberate — it is what the guard
  checks.
- **The budget view is an indirection.** A reader who finds
  `_DocumentEntityBudget` has to be told why the tokenizer's own ceiling is
  wrong here, which is why it carries a docstring longer than its code.
- **The tokenizer's `max_entities` is now reachable with two different
  meanings.** Nothing prevents a future caller from substituting a *larger*
  budget for a prompt. The type is private to this module, which is the only
  thing stopping it.

## Alternatives Considered

- **Write a document-specific splicer.** Shorter and clearer to read, and it
  duplicates the right-to-left ordering and the batching. Rejected: those are
  the two places where a divergence would be silent.
- **Give `Tokenizer.transform` a `max_entities` override parameter.** Simpler
  than a policy view, and it puts a way to weaken a per-request bound directly
  on the prompt path's public API. Rejected.
- **Carry only `policy_version` on `AnalyzedDocument` and re-resolve the policy
  in the protector.** Less coupling, and it admits a window where the two stages
  disagree about the rules. Rejected; the window is 30 seconds wide and the
  failure is silent.
- **Have the protector apply `LabeledSpan.action` directly and skip the
  tokenizer's derivation.** Removes the guard's reason to exist, and requires
  either a new splice or a tokenizer that accepts pre-decided actions. The
  second is a reasonable future change; it was not worth widening the prompt
  path's API for this phase.
- **Mint a session per document.** Removes a parameter and makes the tokens
  useless to the conversation that will quote them. Rejected.

## Implementation Constraints

- Nothing in `app/documents/protection.py` logs a value; its one log line
  carries identifiers, a policy version, and the tokenizer's own counts.
- `ProtectedDocument` carries no mappings. The originals are in the vault, which
  is where restoration reads them from.
- A blocked entity type is refused by *analysis*, before protection begins, so a
  document destined to fail reaches no vault call.
- If protection ever needs to act on the labels without the tokenizer
  re-deriving them, the tokenizer grows an entry point that accepts decided
  actions — it does not get a second implementation.

## As Built (Phase 4)

`app/documents/protection.py`.

`tests/unit/test_document_protection.py` runs the real tokenizer against a vault
that mints real tokens under the real grammar.
`test_no_original_survives_in_the_protected_text` is the assertion the phase
exists for; `test_a_span_that_analysis_labeled_is_never_silently_dropped` drives
a deliberately lossy tokenizer through the guard; and
`tests/security/test_document_analysis_isolation.py::
test_a_document_token_resolves_through_the_pipeline_vault` asserts behaviourally
— not by comparing object identities — that the chat path's vault can read what
the document path wrote.
