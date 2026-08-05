# Threat Model

The vault holds reversible mappings from tokens to original values. It is the
highest-value store in the system: everything else the gateway protects can be
recovered from it. This document enumerates what threatens it and what answers
each threat.

## Vault threats

- **Credential theft** — Redis credentials taken from the environment, an image,
  or a process.
- **Snapshot theft** — an RDB/AOF file, backup, or volume copy taken at rest.
- **Memory inspection** — plaintext read from the gateway or Redis process.
- **Operator abuse** — someone with legitimate infrastructure access reading
  mappings.
- **Cross-session lookup** — resolving a token minted for another session or
  tenant.
- **Token enumeration** — guessing or iterating token identifiers.
- **Key theft** — encryption key material taken from the environment or memory.
- **Replay** — a captured record reinserted, or moved to another namespace.
- **Denial of service** — exhausting the vault so requests fail.
- **Stale data after logout** — mappings surviving the end of a session.
- **Gateway compromise** — the trusted process itself is the attacker.

## Controls

| Threat | Control |
|---|---|
| Credential theft, snapshot theft | Application-layer authenticated encryption — Redis stores ciphertext only, so store access is not value access |
| Cross-session lookup | Tenant- and session-scoped keys; no global lookup by token id |
| Replay, namespace moves | Associated data binds each record to tenant, session, and entity type; a moved record fails authentication |
| Token enumeration | Opaque random token identifiers, not sequential and not timestamped (ADR-0006) |
| Operator abuse | Least privilege, private networking, monitoring |
| Stale data after logout | TTL on every key, plus explicit destruction on logout (ADR-0023) |
| Key theft | Key rotation, a key ring rather than a single key, no key material in logs or audit |
| Denial of service | Rate limiting, bounded entity budgets, bounded batch sizes, fail-closed behaviour |
| In transit | TLS |

## Residual risk

**Gateway compromise is not defended against by these controls.** A compromised
gateway process holds the keys, by construction — it must, to do its job. The
controls above bound what an attacker gets from the *store*, the *network*, and
*another session*; they do not bound what an attacker gets from the trusted
process itself. Reducing that risk is a deployment concern: least privilege,
image provenance, network isolation, and monitoring.

## Pseudonymization risk

Pseudonymization is not anonymization (ADR-0025). Even with every direct
identifier replaced, re-identification remains possible through rare diagnoses,
dates, employers, locations, relationships, public records, writing style, and
repeated context. Surrogates preserve the shape of a value and every
relationship in the surrounding text; that is what makes them readable, and what
makes them re-identifiable.

## Detection risk

The largest residual risk in the system is not the vault — it is detection
quality. The gateway guarantees that *detected* spans are transformed. It cannot
guarantee that every sensitive value is detected. Two shipped defects were
exactly this: a threshold set above the detector's real scores, and a dependency
silently discarding valid matches. Both were fail-open behaviours inside a
fail-closed system.

## Related documents

- [README-risk-awareness.md](README-risk-awareness.md) — tradeoffs in plain terms
- [data-classification.md](data-classification.md) — what is protected and how
- [audit-evidence.md](audit-evidence.md) — what the audit trail proves
