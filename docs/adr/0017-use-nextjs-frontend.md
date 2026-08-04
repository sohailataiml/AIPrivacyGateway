# ADR-0017: Use Next.js for the Interview Frontend

- **Status:** Accepted
- **Date:** 2026-08-04

## Decision

Use Next.js, React, and TypeScript for one role-aware web application.

## Implementation Constraints

The browser never calls the LLM provider or vault directly. Provider and encryption keys remain server-side. API keys are not stored in local storage. Raw prompts and responses do not enter analytics.
