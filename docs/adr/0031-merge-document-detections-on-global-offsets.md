# ADR-0031: Merge Document Detections on Global Offsets, Then Apply Policy

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

Segmentation (ADR-0029) hands the detector overlapping windows on purpose. The
overlap is a privacy control: an entity shorter than
`SEGMENT_OVERLAP_CHARACTERS` is guaranteed to appear whole in at least one
segment, which is what stops a boundary falling mid-value from hiding an
identifier from every recognizer. ADR-0029 states the consequence and defers it:
duplicates "collapse on identity later", in the phase that adds detection.

This is that phase, and "later" turns out to contain four separate decisions.

**The same value is reported more than once.** An entity sitting in an overlap
region is detected by every segment that contains it, at *identical* global
offsets. Something has to decide these are one entity.

**The copies disagree.** Presidio scores a match partly from the words around
it, and a cut changes those words. The same email can score 1.0 in the segment
that saw it in context and lower in the one that saw it at a boundary.

**A cut manufactures fragments, not just duplicates.** A segment ending inside
`marguerite.okonkwo@zzcanary-clinic.test` can still yield a syntactically valid
address ending `…clinic.te`. That is a *different* span from the whole value —
shorter, overlapping it, and equally plausible to the recognizer that produced
it. If it survives alongside the whole value, protection replaces the wrong
characters and leaves part of the original in place.

**Policy has two independent verdicts on a span**: is it confident enough to be
a detection at all (`min_score`), and what should happen to it (`action`). The
order in which those interact with overlap resolution changes which values are
protected.

## Decision

Detections from every segment are merged into one set of document-global spans,
in this order, before anything is labeled:

1. **Promote** each detection to global offsets via `Segment.to_global`, the one
   place segment-local arithmetic is written.
2. **Coalesce** detections sharing an `(entity_type, start, end)` identity into
   one, keeping the **highest** score and the union of the segment indexes.
3. **Select confident** — drop spans below the policy's `min_score` for their
   type.
4. **Resolve overlaps** with `app.detection.overlap.resolve_overlaps`, the same
   severity-first rule the prompt path uses (`architecture.md` §9.4).
5. **Label** each survivor with the policy's action and the pages it touches.

Two of those five carry the reasoning that made this an ADR.

### The highest score wins a coalesce

The segment that saw a value with its context intact is the one that scored it
correctly, and after a cut the context is genuinely different rather than
merely noisier. Taking the maximum is also the fail-closed direction: it can
move a span **over** a policy threshold, never under one.

### Confidence is filtered before overlaps are resolved, not after

The reverse order loses values outright. A sub-threshold `API_KEY` overlapping
an above-threshold `EMAIL_ADDRESS`: severity is the *first* key of the ordering
rule, so resolving first lets the api key win the span and then be dropped for
confidence — leaving nothing protecting those characters at all. Filtering
first lets the address survive and be tokenized.

Filtering first is never worse and is sometimes the difference between a
protected value and a leaked one. It is also the order
`app/tokenization/selection.py` already uses for prompts, so documents and
prompts cannot drift apart on a question this consequential.

### Fragments lose to whole values, by the existing rule

No special case was added for them. A fragment overlaps the whole value it came
from, and the ordering rule prefers the longer span at equal severity and
confidence — so the whole value wins for the same reason it wins anywhere else.

## Consequences

### Positive

- **The overlap's guarantee survives to the output.** Segmentation promises the
  value appears whole in some segment; this makes the whole value the one that
  gets protected.
- **Provenance is preserved.** A span records every segment it was seen in, so
  a merge can be explained after the fact rather than inferred.
- **One rule, two entry points.** Documents and prompts resolve contention
  identically, so a fix to the ordering rule fixes both.
- **The result is deterministic.** Every step is a pure function of its inputs;
  segments are detected concurrently and the answer does not depend on which
  finished first.

### Negative

- **Detection work is duplicated by design.** A value in an overlap region is
  analyzed once per segment that holds it. Overlap is 256 characters against a
  12,000-character segment, so the waste is roughly 2%, and it buys the
  guarantee.
- **A pathological overlap multiplies that cost.** The setting is validated at
  startup to be smaller than the segment size, which bounds it, but a value
  close to the segment size is legal and expensive.
- **Coalescing is identity-based, so near-misses stay separate.** Two detections
  of the same value differing by one character — one including a trailing dot,
  say — are two spans, and resolution picks one. That is the correct outcome and
  it is worth knowing it is resolution doing it, not coalescing.

## Alternatives Considered

- **Deduplicate on the matched text rather than the offsets.** Would collapse
  two *different* occurrences of the same value into one span, so the second
  occurrence would go unprotected. Rejected; this is the failure the phase
  exists to prevent, arriving through the optimisation meant to prevent it.
- **Detect once over the whole document instead of per segment.** Removes the
  merge entirely, and removes segmentation with it — along with the reasons
  segmentation exists: context windows and detection accuracy degrading with
  length. Rejected.
- **Resolve overlaps, then filter by confidence.** Simpler to describe and
  loses values, as above. Rejected.
- **Average the scores of coalesced copies.** Statistically tidier and moves
  spans *under* thresholds, which is the fail-open direction. Rejected.
- **Keep fragments and let protection deal with them.** Pushes an offset
  problem into the stage that splices text, which is the stage where getting it
  wrong is unrecoverable. Rejected.

## Implementation Constraints

- Every function in `app/documents/analysis/spans.py` is pure: no clock, no
  randomness, no I/O, no policy lookup beyond the immutable snapshot.
- Detection is **not** narrowed to the policy's configured entity types.
  Narrowing it recreates defect 7 — the policy's protective default for an
  unconfigured type can never fire if no such entity is ever detected.
- Diagnostics are off and not configurable. A recognizer name is diagnostic
  output for a privileged caller inspecting one prompt; it never travels with a
  document's spans.
- The policy snapshot is resolved once, before the document is opened, and is
  fixed for the whole document. A policy edit cannot apply to half of one.

## As Built (Phase 3)

`app/documents/analysis/spans.py` and `app/documents/analysis/analyzer.py`.

`tests/unit/test_document_analysis_spans.py` tests each stage in isolation and
the composition as a property — including
`test_filtering_first_keeps_the_value_that_resolving_first_would_lose`, which
runs both orders over the same input and asserts the wrong one protects nothing.
`tests/unit/test_document_analysis.py::TestBoundaries` asserts the whole path
against the real segmenter, sliding a value across a boundary and requiring
exactly one span covering it whole.
