# Architecture Decision Records

This directory contains the accepted architectural decisions for the Secure AI Gateway.

Claude Code must read this file and all ADRs with status **Accepted** before implementing architecture-sensitive changes.

## ADR Index

| ADR | Decision | Status |
|---|---|---|
| [0000](0000-adr-process.md) | ADR process | Accepted |
| [0001](0001-use-fastapi.md) | Use FastAPI | Accepted |
| [0002](0002-use-presidio.md) | Use Presidio | Accepted |
| [0003](0003-use-redis-vault.md) | Use Redis vault | Accepted |
| [0004](0004-encrypt-vault-records.md) | Encrypt vault records | Accepted |
| [0005](0005-use-postgresql.md) | Use PostgreSQL | Accepted |
| [0006](0006-use-opaque-session-tokens.md) | Use opaque session tokens | Accepted |
| [0007](0007-provider-abstraction.md) | Provider abstraction | Accepted |
| [0008](0008-fail-closed.md) | Fail closed | Accepted |
| [0009](0009-modular-monolith.md) | Modular monolith first | Accepted |
| [0010](0010-api-key-authentication.md) | API-key authentication | Accepted |
| [0011](0011-privacy-safe-observability.md) | Privacy-safe observability | Accepted |
| [0012](0012-defer-streaming.md) | Defer streaming | Accepted |
| [0013](0013-no-raw-conversation-storage.md) | No raw conversation storage | Accepted |
| [0014](0014-policy-driven-actions.md) | Policy-driven entity actions | Accepted |
| [0015](0015-use-hmac-for-correlation.md) | HMAC correlation | Accepted |
| [0016](0016-use-mock-provider-for-tests.md) | Mock providers in tests | Accepted |

## Claude Code Rule

Before changing any of these areas, verify that the change conforms to the relevant ADR:

- API framework
- Detection engine
- Vault storage
- Encryption
- Durable database
- Token format
- Provider integration
- Failure behavior
- Deployment boundaries
- Authentication
- Observability
- Streaming
- Data retention
- Policy behavior
- Correlation and hashing
- Testing strategy

When a requested implementation conflicts with an accepted ADR, stop and create a proposed superseding ADR before changing the code.


## Frontend Decisions

- [ADR-0017: Use Next.js for the interview frontend](0017-use-nextjs-frontend.md)
- [ADR-0018: Use one role-aware web application](0018-one-role-aware-web-app.md)
- [ADR-0019: Do not persist sensitive data in browser storage](0019-no-sensitive-browser-persistence.md)

## PRD Alignment ADRs

| ADR | Decision | Status |
|---|---|---|
| [0020](0020-encrypted-document-storage.md) | Encrypted object storage for documents | Accepted |
| [0021](0021-user-scoped-document-keys.md) | Bind document decryption to user context | Accepted |
| [0022](0022-batch-vault-operations.md) | Batch vault operations | Accepted |
| [0023](0023-session-destruction-on-logout.md) | Destroy session vault state on logout | Accepted |
| [0024](0024-outbound-payload-attestation.md) | Record outbound payload attestation | Accepted |
| [0025](0025-pseudonymization-risk.md) | Treat pseudonymization as re-identifiable | Accepted |
| [0026](0026-co-reference-safe-default.md) | Preserve indirect co-references | Accepted |

These extend the rule above to four further areas: **document storage and
extraction**, **vault interaction shape**, **session lifecycle**, and
**restoration behavior**.

## Supporting Documents

The ADRs above are the decisions. These describe what follows from them:

- [data-classification.md](../data-classification.md) — every data type, its classification, and the storage, encryption, retention, and logging rules that follow
- [threat-model.md](../threat-model.md) — vault threats, controls, and residual risk
- [audit-evidence.md](../audit-evidence.md) — what an audit record holds, and what it does and does not prove
- [document-processing.md](../document-processing.md) — the document pipeline specification
- [performance.md](../performance.md) — benchmark targets and measurement method
- [observability.md](../observability.md) — metrics, `/metrics`, and runtime alerting
- [README-risk-awareness.md](../README-risk-awareness.md) — tradeoffs and limitations in plain terms
