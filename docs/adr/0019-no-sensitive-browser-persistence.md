# ADR-0019: Do Not Persist Sensitive Data in Browser Storage

- **Status:** Accepted
- **Date:** 2026-08-04

## Decision

Do not store API keys, prompts, responses, mappings, or complete tokens in local storage, session storage, IndexedDB, URLs, or analytics.

## Implementation Constraints

Prefer secure HTTP-only sessions. Local interview mode may keep an API key in memory only.
