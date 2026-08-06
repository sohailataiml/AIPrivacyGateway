# ADR-0026: Preserve Indirect Co-References

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

A protected prompt names an entity by token. The model's answer often refers to
that entity indirectly instead — "the patient", "she", "the customer above",
"the first applicant" — without emitting the token it was given.

It is tempting to resolve those phrases back to the original value: the answer
reads better, and the user knows who is meant anyway. It would also be a
guess. The gateway would be deciding, from natural language, which real person
an indirect phrase denotes, and writing an original value into a position the
model never marked. Where the guess is wrong, the gateway itself introduces the
disclosure — the wrong name attached to the wrong statement.

Restoration is otherwise a mechanical operation: parse tokens, resolve the ones
this tenant and session own, substitute in a single pass. Unknown tokens already
follow policy rather than being guessed at, and the vault never searches other
sessions for a match.

## Decision

Do not automatically restore indirect phrases when the model does not emit the
security token. Restoration substitutes tokens and nothing else.

## Consequences

### Positive

- The gateway never invents a link between a phrase and a person.
- Restoration stays deterministic and inspectable: output differs from provider
  output exactly where a token was resolved.
- No natural-language co-reference model enters the trusted path, with the
  attack surface and failure modes that would bring.
- The safe default holds when the model behaves unexpectedly, which is the case
  that matters.

### Negative

- Responses can read less naturally than a co-reference-resolving version would.
- A user may see "the patient" where they expected a name, and that looks like a
  gap rather than a decision.

## Alternatives Considered

- **Heuristic co-reference resolution.** Guesses, at the exact point where a
  wrong answer is a disclosure. Rejected.
- **Prompting the model to always repeat tokens.** Worth doing as a hint, and
  not a control — it cannot be relied on, so the safe default is still required
  underneath.
- **Rewriting indirect phrases to a neutral placeholder.** Alters provider output
  beyond substitution and can change meaning. Rejected.

## Implementation Constraints

- Restoration operates only on parsed, well-formed tokens; no other span of the
  response is rewritten.
- An unresolved or unknown token follows the configured unknown-token action and
  is never resolved by similarity, proximity, or another session's mappings.
- The behaviour is covered by a test asserting that an indirect reference passes
  through unchanged, so a future "improvement" to restoration cannot quietly
  reverse this decision.
- UI copy explains that indirect references are intentionally not restored,
  rather than presenting them as a failure.
