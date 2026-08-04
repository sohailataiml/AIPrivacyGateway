# Interview Talk Track — Enterprise AI Security Gateway

## Thirty-Second Summary

“I built an Enterprise AI Security Gateway that detects policy-defined sensitive data, replaces it with opaque session-scoped tokens, stores mappings in an encrypted Redis vault, sends only protected text to an LLM provider, and restores authorized values in the response. PostgreSQL stores policies and metadata-only audit records, while the frontend demonstrates the secure flow and operational controls.”

## Why a Gateway?

A chatbot solves one experience. A gateway creates a reusable control point for privacy, policy, authentication, rate limiting, audit, observability, and future provider routing.

## Why Tokenization?

Redaction can destroy context. Reversible tokenization preserves entity type and repeated references, but requires a secure stateful vault. Policy selects allow, tokenize, redact, pseudonymize, or block.

## Why Opaque Tokens?

`PERSON_1` is guessable and may occur naturally. Opaque random tokens are harder to fabricate and are restored only within the correct tenant and session.

## Why Redis and PostgreSQL?

Redis handles short-lived TTL mappings. PostgreSQL handles durable tenants, API clients, policies, provider metadata, and audit events.

## Why Presidio?

Presidio is an extensible baseline, not a guarantee. The system adds custom recognizers, regex, checksums, allowlists, context, thresholds, and evaluation.

## What Does Fail Closed Mean?

If detection, policy, tokenization, vault persistence, or restoration fails, the request stops. There is no direct-provider fallback.

## Cross-Tenant Protection

Tenant identity comes from authentication. Redis keys, encryption associated data, repository queries, and restoration all require tenant and session context.

## Why No Raw Prompt Storage?

Logs and audit systems can become secondary sensitive-data stores. The project stores metadata, counts, actions, timing, policy version, and keyed HMACs—not raw text.

## Biggest Risk

Detection quality. The gateway can guarantee transformation of detected spans, not perfect detection of every possible sensitive value.

## Fabricated Tokens

Unknown tokens remain protected. The gateway never searches other sessions or guesses values.

## Streaming

Streaming is deferred because tokens can split across chunks. A future version must buffer partial tokens and restore only complete authorized tokens.

## Production Next Steps

OIDC, managed KMS, Redis HA, egress allowlists, organization-specific detector evaluation, Kubernetes, SIEM integration, additional providers, and streaming-safe restoration.

## Honest Limitations

No detector has perfect recall; generic PII detection is not full PHI understanding; tokenization still sends surrounding context; this is not a compliance certification; version 1 is synchronous; demo data is synthetic.

## Closing Statement

“The architectural boundary is the main result: provider code can only receive a protected request type, reversible values exist only in an encrypted TTL vault, and observability is metadata-only.”
