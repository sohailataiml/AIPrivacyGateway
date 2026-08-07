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

## Document storage threats

Uploaded documents add a second high-value store. The shape of the problem is
the vault's, one level deeper: a document belongs to a user, not merely to a
tenant, and it is bulk Restricted content that has never been through detection.

- **Bucket compromise** — object storage credentials, a volume copy, or a
  misconfigured public bucket.
- **Object relocation** — an attacker with bucket write access copies one
  principal's object onto another's key.
- **Cross-user read** — a document id from another user in the same tenant.
- **Key enumeration** — guessing object keys to find documents.
- **Chunk manipulation** — reordering, duplicating, dropping, or truncating
  frames within a stored object to alter a document without breaking it.
- **Type confusion** — an executable or archive stored under a `.pdf` or `.txt`
  name, to be handed to a parser later.
- **Filename spoofing** — bidirectional override characters that make a stored
  name render as something other than what it is.
- **Filename disclosure** — a name that identifies a person and a condition,
  leaking through a log line, a metric label, or an error message.
- **Resource exhaustion** — an upload with no `Content-Length`, or one that
  simply never stops, consuming memory or storage.
- **Orphaned multipart uploads** — abandoned parts that no listing shows and
  that are billed until something removes them.
- **Torn state** — a row that claims a document is stored when the object is not
  there, or an object nothing points at.

### Controls

| Threat | Control |
|---|---|
| Bucket compromise | Application-layer AEAD (ADR-0020); the store holds ciphertext, is told nothing about the content type, and is private by default |
| Object relocation, cross-user read | Per-document HKDF keys plus associated data binding tenant, user, and document (ADR-0021) — the copy authenticates as nobody's document. The scoped query is the first layer, the cryptography the second |
| Key enumeration | Opaque random storage keys carrying no tenant, user, filename, or extension; a key is not a credential |
| Chunk manipulation | Chunk index and a final-chunk flag inside each frame's AAD — reorder, duplicate, drop, and truncate all fail authentication |
| Type confusion | Extension, declared MIME type, and magic bytes must agree; signature-less types are additionally checked against every other type's signature |
| Filename spoofing | Bidirectional control characters rejected, and the name is rejected rather than repaired |
| Filename disclosure | Stored encrypted, returned only to its owner, absent from the status route, and swept for by the canary suite across logs, SQL, metrics, and responses |
| Resource exhaustion | Declared length checked up front and the real byte count checked as it streams; memory bounded by chunk size rather than document size |
| Orphaned multipart uploads | Explicit abort on any failure including cancellation, verified against live S3; a bucket lifecycle rule as backstop |
| Torn state | Row before object, `stored` set last, object deleted before row |

### What this does not defend against

- **A legitimate user uploading a document they should not have.** Access
  control is per principal; the gateway has no view of what a principal is
  entitled to upload.
- **Malicious document content.** Phase 1 checks headers, not structure. A
  crafted PDF is stored as opaque bytes and handed back to its owner unchanged;
  the exposure begins when extraction parses it, which is where a sandboxed,
  bounded extraction path becomes load-bearing rather than merely planned.
- **Traffic analysis.** Object sizes and upload timings are visible to anyone
  with bucket access, and a ciphertext's length still approximates its
  plaintext's.

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
