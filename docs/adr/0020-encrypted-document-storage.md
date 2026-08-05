# ADR-0020: Use Encrypted Object Storage for Uploaded Documents

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Document upload extends the gateway from prompt text to files. An uploaded
document is Restricted data under [data-classification.md](../data-classification.md):
it holds the original values the gateway exists to protect, in bulk, before any
detection has run.

PostgreSQL is the wrong home for it. Storing document bodies in the durable
database would put Restricted content in the same store as audit metadata,
which ADR-0013 keeps free of raw conversation content, and would make every
backup and read replica a copy of unprotected originals.

Transport encryption and provider-side encryption at rest are also not enough.
Both leave the storage operator able to read the object.

## Decision

Store uploaded documents in S3-compatible object storage — MinIO in the
Compose and interview environment, settled by ADR-0027 — with
**application-layer encryption**. PostgreSQL stores metadata only.

The gateway encrypts before the bytes leave the process and decrypts after they
return. Storage-provider encryption, where present, is defence in depth and
never the only control.

## Consequences

### Positive

- Restricted document bodies never enter the durable relational database.
- The object store sees ciphertext only; a bucket compromise yields no
  plaintext without the key hierarchy of ADR-0021.
- Object storage is the right shape for large binary content — the database
  keeps small, queryable, metadata-only rows.
- MinIO gives the interview environment a real S3 API without cloud credentials.

### Negative

- A second stateful dependency to run, health-check, and fail closed against.
- Encrypting in the application forecloses server-side features that need
  plaintext, such as storage-side content indexing.
- Key management becomes the gateway's problem, not the provider's.

## Alternatives Considered

- **Bytes in PostgreSQL (`bytea` or large objects).** Puts Restricted content in
  the audit database and bloats backups. Rejected.
- **Object storage with provider-managed encryption only (SSE-S3, SSE-KMS).**
  The operator can read the object. Rejected as the sole control; acceptable
  underneath application-layer encryption.
- **Local filesystem volume.** No durability story, no multi-instance story,
  and the same plaintext-at-rest problem.

## Implementation Constraints

- Encrypt with AES-256-GCM using a per-document data key (ADR-0021), before the
  first byte is written.
- PostgreSQL stores identifiers, content type, sizes, checksums, timestamps, and
  processing status — never document bytes and never extracted text.
- Extracted text is Restricted. Prefer not retaining it; if retained, it is
  encrypted under the same hierarchy and to the same retention rules.
- Temporary plaintext files created during extraction are deleted immediately,
  including on the error path.
- Object-store unavailability fails the request closed, per ADR-0008. There is
  no unencrypted fallback path.
- Document identifiers follow the canonical random-id grammar — not sequential,
  not timestamped, consistent with the token-id rule in ADR-0006.
