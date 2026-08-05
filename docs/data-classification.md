# Data Classification Matrix

Every kind of data the gateway touches, and the rules that follow from its
classification. When a new data type is introduced, it is added here before it
is stored.

| Data | Classification | Storage | Encryption | Retention | Logging |
|---|---|---|---|---|---|
| Original document | Restricted | Object store | App-layer AEAD | Policy-defined | Never |
| Extracted text | Restricted | Prefer none | Required if retained | Minimal | Never |
| Original entity value | Restricted | Redis | App-layer AEAD | Session TTL | Never |
| Security token | Confidential | Redis / protected payload | TLS | Session TTL | Full token prohibited |
| Protected prompt | Confidential | Not persisted | TLS | Request lifetime | Never |
| Restored response | Restricted | Not persisted | TLS | Request lifetime | Never |
| Audit metadata | Internal | PostgreSQL | At rest + TLS | Policy-defined | Allowed |
| Provider key | Secret | Secret manager | Managed | Rotated | Never |

## Reading the columns

- **Classification** drives every other column. Restricted is the strictest:
  originals, or anything from which originals are directly recoverable.
- **Storage** is the only place the data is permitted to live. "Not persisted"
  means it exists in process memory for the life of one request and is written
  nowhere.
- **Encryption** — "App-layer AEAD" means the gateway encrypts before the bytes
  leave the process (ADR-0004, ADR-0020). Transport or provider-side encryption
  underneath it is defence in depth, never the only control.
- **Retention** — "Session TTL" means the record expires on its own and is
  destroyed sooner on logout (ADR-0023).
- **Logging** — "Never" means the value must not reach stdout, structured log
  fields, metric labels, error messages, or exception context, at any log level.

## Notes that are easy to get wrong

- **Extracted text is as sensitive as the document it came from.** It is
  plaintext originals in bulk, minus the file format. The default is not to
  retain it; temporary files are deleted immediately, including on error paths.
- **A full security token is Confidential, not Internal.** A token is useless
  without the vault, but it is the handle to a Restricted value, so full tokens
  are never logged. Shortened forms are acceptable for display and correlation.
- **Pseudonymized values are Restricted.** A surrogate looks synthetic and is
  not (ADR-0025); every rule that applies to an original applies to it.
- **Audit metadata is Internal only because of what it excludes.** Counts,
  versions, timings, aliases, and keyed HMACs. The moment a raw value enters an
  audit row, that row is Restricted and the design is broken — see
  [audit-evidence.md](audit-evidence.md).
- **Third-party libraries log too.** Any dependency that touches message content
  needs its logger floor raised before it ships; this has already been the cause
  of two defects.

## Related decisions

- ADR-0004 — encrypt vault records
- ADR-0011 — privacy-safe observability
- ADR-0013 — no raw conversation storage
- ADR-0020 — encrypted document storage
- ADR-0021 — user-scoped document keys
- ADR-0025 — pseudonymization is re-identifiable
