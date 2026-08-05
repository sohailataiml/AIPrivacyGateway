# ADR-0023: Destroy Session Vault State on Logout

- **Status:** Accepted
- **Date:** 2026-08-04

## Context

Vault mappings already expire: every key the vault writes carries a TTL, so
reversible data disappears on its own. But a TTL is a ceiling, not an
instruction. Between a user finishing work and the TTL firing, the encrypted
originals for that session remain in Redis, and the vault is the highest-value
store in the system — [threat-model.md](../threat-model.md) lists snapshot
theft, operator abuse, and memory inspection against exactly this window.

A user who logs out has stated that the session is over. Leaving reversible
mappings alive for the remainder of the TTL means the system's data footprint
is governed by a timer rather than by the user's intent.

## Decision

Logout deletes the session's mappings, indexes, metadata, and any usable
session key material. TTL is defence in depth, not the primary mechanism.

## Consequences

### Positive

- The reversible-data window closes when the user says it does.
- A snapshot taken after logout contains nothing for that session.
- The system has an affirmative deletion story, rather than only an expiry one.
- Explicit deletion is demonstrable in a way an unexpired TTL is not.

### Negative

- Requires a logout concept the API-key-authenticated backend does not have
  today; the browser session of ADR-0019 is what supplies it.
- Deletion must itself fail closed and be observable — a logout that silently
  half-deletes is worse than one that errors.
- A user who closes the tab without logging out still relies on TTL.

## Alternatives Considered

- **TTL only.** Simple, already implemented, and leaves the window open for the
  full session lifetime after the user has finished. Rejected as sufficient.
- **Shortening the TTL instead.** Trades the problem for broken long sessions,
  and still leaves a window. Rejected.
- **Deleting on the next request after logout.** There may not be one.

## Implementation Constraints

- Deletion removes record keys, index keys, and the session metadata set in one
  operation, and never touches a key outside the session's own namespace.
- Deletion is scoped by tenant and session, like every other vault method.
- Where session key material is stored rather than derived, logout destroys it;
  where it is derived from the session identity, destroying the mappings is what
  makes it unusable, and that reasoning is recorded rather than assumed.
- Logout deletion fails closed: a logout that cannot reach the vault reports an
  error rather than reporting success.
- The count of records removed is audit-worthy metadata; the tokens and values
  removed are not.
- Deleting an already-deleted or unknown session is not an error and reveals
  nothing about whether it existed.
