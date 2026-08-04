# ADR-0002: Use Microsoft Presidio as the Primary Detection Framework

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

The gateway needs extensible sensitive-data detection for common PII types while allowing custom recognizers, confidence thresholds, context words, allowlists, and organization-specific patterns.

## Decision

Use Microsoft Presidio Analyzer as the primary detection framework.

Combine it with:

- spaCy NER where configured.
- Regex and checksum recognizers.
- Custom enterprise recognizers.
- Tenant-specific allowlists and denylists.
- Explicit overlap resolution implemented in the gateway.

## Consequences

### Positive

- Extensible recognizer architecture.
- Good baseline coverage for common PII.
- Supports custom recognizers.
- Avoids building the entire detector framework from scratch.

### Negative

- Detection is probabilistic and cannot guarantee perfect recall.
- Generic PII detection is not equivalent to full PHI detection.
- Model and recognizer quality must be evaluated with organization-specific data.

## Alternatives Considered

- spaCy only
- Hugging Face NER only
- Regex only
- Commercial privacy APIs
- External LLM-based detection

## Implementation Constraints

- Detection failures must fail closed.
- Unsupported languages must not silently bypass detection.
- Medical condition detection must not be claimed unless a dedicated recognizer has been implemented and tested.
- Public diagnostic endpoints must not return matched values by default.
