# ADR-0025: Treat Pseudonymization as Re-Identifiable

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

The `PSEUDONYMIZE` action replaces a value with a different value of the same
shape: digits stay digits, letters keep their case, separators survive. A
prompt therefore still reads naturally, which is the point — the model sees
something that parses as an email address or a phone number rather than an
opaque token.

That readability is also the risk. A surrogate preserves length, character
classes, and every relationship in the surrounding text. As
[threat-model.md](../threat-model.md) and
[README-risk-awareness.md](../README-risk-awareness.md) both record, rare
diagnoses, dates, employers, locations, relationships, and repeated context can
re-identify a subject with no direct identifier present at all.

Calling this "anonymization" would be a compliance claim the system cannot
support, and would invite operators to route high-risk entity types through it.

## Decision

Pseudonymization is not anonymization. Surrogates are session-scoped and
non-deterministic across sessions, and the residual re-identification risk is
documented rather than papered over.

## Consequences

### Positive

- Two sessions containing the same original value produce unrelated surrogates,
  so nothing can be linked across sessions by matching surrogates.
- Prompt coherence is preserved for the cases that need it, with the tradeoff
  stated rather than implied.
- Operators choosing `PSEUDONYMIZE` for a high-risk entity type are choosing it
  knowingly.

### Negative

- Surrogates deliberately leak length and character class.
- Cross-session analytics on pseudonymized values are impossible by
  construction. That is intended, and it is a real capability given up.
- The action is weaker than `TOKENIZE` while looking more natural, which is
  precisely why it needs saying.

## Alternatives Considered

- **Deterministic surrogates across sessions.** Enables consistency and
  linkage-based re-identification in the same stroke. Rejected — it is the
  property ADR-0006 rejected for tokens, in a friendlier costume.
- **Removing the action.** Some prompts genuinely degrade under opaque tokens.
  Rejected; the action is kept and bounded.
- **Describing it as anonymization.** Not defensible.

## Implementation Constraints

- Surrogates derive from the session-scoped keyed fingerprint, so the same value
  yields the same surrogate within a session and an unrelated one in any other.
- The derivation is unpredictable without the fingerprint key; the key is never
  logged, audited, or exposed.
- Documentation and UI never present pseudonymization as anonymization, and the
  shape-leak is stated where the action is described.
- `TOKENIZE` remains the default for entity types where shape itself is
  sensitive; `BLOCK` remains correct for the highest-risk types.
- Pseudonymized values are Restricted data throughout, and are subject to every
  rule that applies to originals.
