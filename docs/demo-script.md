# Interview Demo Script — Enterprise AI Security Gateway

**Target duration:** 8–10 minutes  
**Data:** Synthetic only

## Opening

Explain that this is an enterprise control point between applications and external LLMs. Raw detected values are replaced before provider transmission, mappings are encrypted and expire, and restoration is tenant- and session-scoped.

## Secure Chat

Submit:

```text
Please summarize this follow-up:
Patient Avery Example can be reached at avery@example.test or 202-555-0148.
```

Point to the Privacy Inspector and explain detection, policy, tokenization, vault storage, provider invocation, and restoration.

## Policy Block

Submit:

```text
Please send this SSN to the model: 123-45-6789.
```

Show that the request is blocked before provider invocation.

## Dashboard

Show request volume, entity counts, blocks, gateway overhead, provider latency, and recent privacy events. Emphasize metadata-only storage.

## Audit

Open successful and blocked events. Show policy version, entity/action counts, provider alias, timing, and safe result code. Confirm raw text is absent.

## Policy

Show PERSON and EMAIL as TOKENIZE, US_SSN as BLOCK, immutable versioning, session TTL, and provider/model allowlist.

## Health and Failure

Show dependency health and explain fail-closed behavior. Optionally disable Redis and show `VAULT_UNAVAILABLE` while verifying the provider mock received no call.

## Architecture and ADRs

Discuss modular monolith, Presidio, encrypted Redis vault, PostgreSQL, opaque tokens, protected provider request types, no raw conversation persistence, and mocked provider tests.

## Close

“The chat UI is a demonstration client. The main product is the privacy and policy boundary between enterprise applications and model providers.”

## Checklist

- clean startup
- synthetic data only
- mock provider enabled
- seeded dashboard
- browser storage inspected
- blocked SSN never reaches provider
- architecture page ready
