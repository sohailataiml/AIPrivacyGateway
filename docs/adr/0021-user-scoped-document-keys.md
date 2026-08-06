# ADR-0021: Bind Document Decryption to User Context

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

ADR-0020 encrypts documents at the application layer. That decision is only as
strong as what the ciphertext is bound to. A single deployment-wide key would
mean any authenticated caller who can name an object id can have it decrypted —
possession of an identifier becomes possession of the content.

The vault already solved this shape of problem for token mappings: every
`TokenVault` method is scoped by tenant *and* session, there is no global lookup
by token id, and the encryption associated data binds each record to the
identity it was minted under, so a record moved to another namespace fails
authentication rather than decrypting into the wrong context.

Documents need the same property, extended by one level: a document belongs to a
user, not merely to a tenant.

## Decision

Decryption requires **tenant ID, user ID, and document ID** under a
per-document key hierarchy. A per-document data key is derived from — or wrapped
by — key material identified by that triple, and the triple is bound into the
authenticated encryption's associated data.

Supplying the wrong tenant, the wrong user, or the wrong document id produces an
authentication failure, not plaintext.

## Consequences

### Positive

- A leaked or guessed document id is not sufficient to read a document.
- Cross-tenant and cross-user reads fail cryptographically, not only in the
  repository query — the same belt-and-braces posture the vault already uses.
- Per-document keys bound the blast radius of any single key compromise.
- Key rotation can proceed per document rather than as one flag-day re-encrypt.

### Negative

- Key derivation on every read adds latency to the document path.
- Legitimate document sharing between users is not expressible without a
  deliberate re-encryption or a re-wrap step. That is the intended default.
- More key material to manage, rotate, and monitor.

## Alternatives Considered

- **One deployment-wide document key.** Simplest, and makes an object id a
  bearer credential. Rejected.
- **Per-tenant key only.** Blocks cross-tenant reads but leaves every user in a
  tenant able to decrypt every other user's uploads. Rejected.
- **Authorization checks in the repository layer alone.** A single missing
  `WHERE` clause becomes a data breach, with nothing underneath it. Rejected as
  the sole control; retained as the first layer.

## Implementation Constraints

- Associated data includes tenant, user, document, content type, and schema
  version, so a record cannot be replayed into another context or reinterpreted
  under another schema.
- No API accepts a document id alone. Tenant and user come from authentication,
  never from the request body or a query parameter.
- There is no global "decrypt by document id" helper, mirroring the vault's rule
  that no global lookup by token id exists.
- Decryption failure is reported with a safe error code that does not
  distinguish "wrong user" from "no such document" — absence and denial look
  identical to the caller, as they do for vault tokens.
- Key material is never written to logs, audit records, or metrics labels.

## As Built (Phase 1)

**Derivation, not wrapping.** The ring key encrypts nothing. Each document's
data key is derived with HKDF-SHA256 from the ring key, a per-document 16-byte
salt stored in the object header, and an `info` string carrying the
`tenant | user | document` triple. Two documents therefore never share a key,
and a key recovered from one reveals nothing about another.

**What the associated data carries.** Every frame's AAD is a
length-prefixed join of: a domain separator, the format version, tenant, user,
document, content type, schema version, purpose, chunk index, and whether the
chunk is the last one. Each field defeats a distinct attack, and each has its
own test in `tests/security/test_document_crypto_isolation.py`:

| Field | What it stops |
|---|---|
| tenant, user, document | An object relocated to another principal |
| content type, schema version | The same bytes reinterpreted as another type |
| purpose | A sealed filename opened as a body, or the reverse |
| chunk index | Frames reordered or duplicated within a document |
| final flag | A document truncated part-way |

Dropping any one of them removes exactly one defence while every round-trip
test keeps passing, which is why they are tested individually.

**Filenames are sealed too.** A filename such as
`Okonkwo-Vasquez-oncology-summary.pdf` names a person and a specialty before the
file is opened, so it is Restricted. It is sealed under the same per-document
key with `purpose = "filename"` and stored in the `filename_ciphertext` column.
The two ciphertexts are not interchangeable.

**Who "user" is, for now.** The gateway authenticates API keys rather than
people, so the authenticated subject is the API key id. Two keys in the same
tenant are two different principals and cannot read each other's documents.
`app/api/v1/documents.py::_user_id` is the single place that changes when a user
model arrives.

**Ring separation.** Documents use `DOCUMENT_ACTIVE_KEY_ID` and `DOCUMENT_KEY_*`,
which are separate from the vault's `VAULT_*` ring on purpose: the two protect
data with different lifetimes and rotate on different schedules.

**Not built in this phase.** No key rotation tooling and no re-encryption or
re-wrap path, so the sharing story described above remains unexpressible rather
than merely discouraged. The format supports rotation — the key id travels with
each object — but nothing yet drives it.
