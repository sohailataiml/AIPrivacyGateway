# ADR-0018: Use One Role-Aware Web Application

- **Status:** Accepted
- **Date:** 2026-08-04

## Decision

Use one frontend with role-aware routes instead of separate user and administrator deployments.

## Implementation Constraints

Backend scopes remain authoritative. UI route guards are not security controls.
