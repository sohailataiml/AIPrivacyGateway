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

```text
/login
/chat
/dashboard
/sessions
/sessions/[sessionId]
/audit
/audit/[requestId]
/policies
/policies/[policyId]
/providers
/health
/architecture
/about
```

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

Support policy list, version history, entity actions, thresholds, provider/model allowlist, TTL, JSON preview, validation, and save-as-new-version. Weakening a control requires explicit confirmation.

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
