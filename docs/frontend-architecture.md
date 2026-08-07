# Frontend Architecture — Enterprise AI Security Gateway

**Status:** Implementation baseline  
**Audience:** Frontend engineers, security engineers, Claude Code

## 1. Product Intent

The frontend makes the gateway's invisible security boundary understandable. It is not a chatbot product boundary; it is a demonstration and operations layer over the Enterprise AI Security Gateway.

The application has two role-oriented surfaces in one web application:

1. **Secure Chat Workspace**
2. **Security and Operations Console**

The browser never communicates directly with Redis, PostgreSQL, or an LLM provider.

## 2. Primary Personas

- **Enterprise User:** submits prompts and receives restored answers.
- **Security Analyst:** reviews metadata-only audit, policy, entity, and health information.
- **Administrator:** maintains policy versions and approved provider aliases.
- **Interview Reviewer:** needs to understand architecture, tradeoffs, and value quickly.

## 3. Technology Stack

- Next.js App Router
- React and TypeScript
- Tailwind CSS
- shadcn/ui or equivalent accessible primitives
- TanStack Query
- React Hook Form and Zod
- Recharts
- Vitest and React Testing Library
- Playwright

Pin stable versions at implementation time.

## 4. Routes

Built:

```text
/chat
/policies
/policies/[policyName]
/policies/[policyName]/test
```

Specified, not built:

```text
/login  /dashboard  /sessions  /sessions/[sessionId]  /audit
/audit/[requestId]  /providers  /health  /architecture  /about
```

The policy segment is `[policyName]`, not `[policyId]` as originally specified.
Every policy version row has its own uuid, so no single id is stable across the
history being managed; the name is what the repository, the unique constraint,
and the API path all key on (ADR-0037).

## 5. Role Model

### User
- invoke chat
- view privacy metadata for own requests
- delete own sessions

### Security Analyst
- view dashboard
- view privacy-safe audit and session metadata
- view policy and provider health

### Administrator
- analyst permissions
- create new policy versions
- enable or disable approved provider aliases

Frontend route guards improve usability only. Backend scopes remain authoritative.

## 6. Secure Chat Workspace

The page contains:

- provider, model, and policy display
- conversation panel
- prompt composer
- Privacy Inspector
- request ID and latency
- clear-session action
- synthetic demo prompts

Privacy Inspector stages:

```text
Validating
Detecting sensitive data
Applying policy
Tokenizing
Securing mappings
Calling provider
Restoring authorized values
Completed
```

Safe metadata:

- entity types and counts
- actions
- policy version
- timing
- unknown token count

Never display original values, complete tokens, encrypted vault records, or provider keys.

## 7. Security Dashboard

Cards:

- requests
- entities detected
- entities tokenized
- blocked requests
- average gateway overhead
- provider success rate
- active sessions
- dependency health

Charts:

- requests over time
- entities by type
- policy actions
- provider usage
- latency percentiles
- safe error codes

## 8. Session and Audit Views

Session metadata may include shortened session ID, mapping count, entity-type counts, TTL, provider alias, and status.

Audit metadata may include request ID, policy version, provider/model alias, character counts, entity/action counts, latency, and result code.

Raw prompt and response content are unavailable by design.

## 9. Policy Manager

**Built (ADR-0037).**

`/policies` lists each policy with its active version, a draft badge when one is
open, entity and enabled counts, and the last published time. An empty list says
the tenant has no policies rather than showing a blank page, and a refusal is
shown with the gateway's own code — the two states are distinguishable, because
"no policies" read as a fact about the tenant when it was really a permissions
problem would be actively misleading.

`/policies/[policyName]` shows metadata, the entity rule table, version history,
and the draft controls. The rule table is editable only while a draft is open;
otherwise its controls are disabled rather than hidden.

Draft edits live in component state and are sent only on save. Nothing is
written to `localStorage`, `sessionStorage`, `IndexedDB`, or a cookie — a rule's
description is free text an operator may paste an identifier into, and ADR-0019
keeps browser storage clear of anything a caller typed. Reloading therefore
loses unsaved edits, which is the honest consequence of that choice.

Publishing requires explicit confirmation. The dialog states what will change,
warns about anything that weakens a control, and refuses when the backend has
reported the draft invalid. It never publishes on mount or on Enter.

Version history and the diff are view-only, and the diff is **fetched from the
backend**. Reconstructing historical policy state in the browser would let the
UI disagree with the database about what version 3 contained, and the whole
value of an immutable version is that there is one answer.

New entity rules are seeded from `GET /v1/detectors/entities`. The frontend has
no entity catalog, no default thresholds, and no fallback policy: those belong
to the detector, and a copy here would drift.

`/policies/[policyName]/test` is the playground. It renders spans from offsets,
because the API returns no matched text, and shows *provider would not be
called* when any span resolves to `BLOCK`.

### 9.1 Authorization in the UI

The frontend hides controls a caller cannot use. That is a convenience and
nothing more — `policies:read`, `policies:write`, and `policies:test` are
enforced by the backend, and a hidden button is not a control.

## 10. Provider and Health Pages

Provider page shows aliases, model aliases, enabled status, health, timeout policy, and storage-policy indicator. Secrets are never displayed.

Health page shows coarse status for gateway, detector, Redis, PostgreSQL, provider, and audit queue without exposing hostnames or credentials.

## 11. Architecture Page

Explain system purpose, data flow, trust boundaries, token lifecycle, fail-closed behavior, ADR choices, and limitations.

## 12. State Management

- TanStack Query for server state
- React Hook Form for forms
- local state for transient UI
- secure HTTP-only session preferred
- in-memory API key permitted for local interview mode

No API keys in browser storage, URLs, analytics, or console logs.

## 13. API Client Rules

- one typed client
- attach authentication
- propagate request IDs
- safe error mapping
- retry idempotent reads only
- never retry chat automatically
- never log bodies
- align types with OpenAPI

## 14. Model Output Safety

Render plain text initially. Sanitize Markdown with a strict allowlist when added. Never render unsanitized HTML.

## 15. Accessibility

Keyboard navigation, visible focus, semantic headings, accessible tables, chart text summaries, non-color status cues, and responsive layouts are required.

## 16. Folder Structure

```text
frontend/
├── app/
├── components/
│   ├── layout/
│   ├── chat/
│   ├── privacy/
│   ├── dashboard/
│   ├── tables/
│   ├── forms/
│   └── ui/
├── lib/
│   ├── api/
│   ├── auth/
│   ├── schemas/
│   └── formatting/
├── hooks/
├── tests/
│   ├── unit/
│   └── e2e/
├── package.json
└── next.config.ts
```

## 17. Required Tests

- complete secure chat flow
- policy-blocked request
- Privacy Inspector rendering
- no credential persistence
- audit page contains no raw content
- no decrypt operation in session UI
- unauthorized route behavior
- policy editing creates a new version
- model output escaped or sanitized
- keyboard and responsive smoke tests

## 18. Definition of Done

The primary demo works from a clean environment, exposes no mappings or secrets, persists no credentials or conversations in browser storage, accurately reflects backend privacy metadata, and communicates the architecture in under three minutes.
