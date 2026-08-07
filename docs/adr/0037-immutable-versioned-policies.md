# ADR-0037: Immutable Versioned Policies with a Draft-and-Publish Workflow

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

The policy engine has been configuration-driven since Phase 2: entity rules,
thresholds, actions, provider allowlists, and session TTL all live in a stored
JSON document, and `PolicySnapshot` freezes one version for the life of a
request. Adding an entity type has never required a change to the tokenizer or
the vault.

None of that was visible or editable. The only way to change a policy was to
write a row directly, and the only way to see one was to read the database.
That makes an operator's central question — *what is the gateway enforcing right
now, and what happens if I change it* — unanswerable without a psql session.

Making it editable is where the risk is. A policy is not ordinary
configuration: lowering a threshold or switching `BLOCK` to `TOKENIZE` changes
what leaves the building. Three failure modes matter more than convenience:

- **Editing what is live.** A save that mutates the active policy applies
  mid-conversation. A request that already resolved a snapshot would then be
  protected by rules its later stages never agreed to.
- **Losing the record.** If publishing overwrites a row, "what was version 3"
  becomes unanswerable, and an audit trail that cannot reconstruct the policy in
  force at a point in time is not an audit trail.
- **Testing against production traffic.** The natural way to check a rule is to
  send real text through it, which is also the way to leak that text.

## Decision

**Published policy versions are immutable. Edits happen on a draft. Publishing
creates a new version and never alters an old one.**

### The lifecycle

```
Active version → Create draft → Edit → Validate → Publish → New active version
                     ↑                                          │
                     └────────── previous versions unchanged ───┘
```

A `policies.status` column carries `draft` or `published`. `create_draft` copies
the active version's document to a new row at the next version number;
`publish_draft` flips it to `published`, sets `published_at`, and deactivates
its predecessors. **The only column that ever changes on an already-published
row is `is_active`.** Documents, versions, and timestamps are written once.

Concurrency is settled by the database, not by application logic: a partial
unique index gives one draft per `(tenant_id, name)`, so two simultaneous
"create draft" calls produce an `IntegrityError` for the loser rather than a
silent overwrite of the winner's edits.

### `PolicySnapshot` is unchanged

This is the property the whole design protects, and it needed no code to hold.
A snapshot is a frozen value built from a document at resolution time, not a
view onto a row. Nothing published afterwards can reach a request already
holding one — there is no path from a database write to an in-flight snapshot,
because the snapshot does not read the database again.

### Policies are keyed by name, not by id

Every version row has its own uuid, so no single id is stable across the history
an operator manages. `(tenant_id, name, version)` is what the repository and the
unique constraint already used, and the routes follow it:
`/v1/policies/{policy_name}`.

### Entity rules gained operator-facing fields

`enabled`, `priority`, `recognizer`, and `description`, all optional with
defaults so every document written before they existed parses to exactly the
behaviour it had.

**`enabled` fails safe.** A disabled rule is dropped from the snapshot, so its
entity type resolves through `UNKNOWN_ENTITY_ACTION` — which is `TOKENIZE`, not
`ALLOW`. Unticking a box removes *that configuration*; it does not release the
value. Sending a type in clear text requires setting `action=ALLOW`, which is a
deliberate, reviewable edit rather than a side effect of a checkbox.

**`priority` is recorded but not wired into overlap resolution.** Severity-first
resolution (ADR-0031) decides which of two overlapping spans wins. Letting a
policy field quietly reorder that would change detection behaviour Phase 3
pinned down with tests, so the field is displayed and stored and nothing more.

### The detector catalog is derived, never restated

`GET /v1/detectors/entities` reads `app.detection.entities` — the module that
already defines the gateway's vocabulary. Types, default thresholds, and
severities are read from it, so adding a type to the detector surfaces it in the
policy editor with no other change. The frontend keeps no catalog of its own.

The catalog exposes no patterns. A regex that finds API keys is a map of what a
credential looks like here, and the catalog is readable by anyone with
`policies:read`.

### The playground detects and stops

`POST /v1/policies/test` resolves a named version — including an open draft —
builds a snapshot, detects, and reports each span's offsets and intended action.
It does not tokenize, write a vault mapping, call a provider, persist the input,
or log it. Those are properties of code that is never called, not of a flag.

**Version resolution differs between the playground and validation, on
purpose.** Omitting `version` on the playground means "what does this policy
do", and for a policy nobody is editing that is the live one, so it falls back
to the active published version. Validation has no such fallback: it reports on
the open draft or refuses. Reporting "valid" about a published version to an
operator asking about a draft they had not created would be a reassuring answer
to a question nobody posed.

Results carry **offsets only**. `/v1/detect` returns matched text when
privileged diagnostics are on; this endpoint does not offer that even then,
because its whole purpose is to be run against realistic input while designing a
policy — exactly the circumstance in which a response is pasted into a ticket.

### Authorization is two-tier

| Scope | Grants |
|---|---|
| `policies:read` | list, versions, diffs, catalog, validate |
| `policies:write` | create, edit, discard, publish |
| `policies:test` | the playground |

Validation is read-scoped because checking a draft changes nothing. The
playground is separate from `policies:read` because it accepts caller-supplied
text and spends detector time, and separate from `detect:invoke` because it
answers a different question against a policy the caller names.

Backend scopes are the control. The frontend hides buttons as a convenience, and
that is all it is.

### Audit

Draft created, updated, discarded, validated, and published each emit a
structured event carrying policy name, from/to version, change count, principal,
and outcome. The keys are added to `ALLOWED_EVENT_KEYS`; the deny-by-default
allowlist would otherwise drop them silently, as it did to the document pipeline
in defect 20.

**The policy document is never logged.** An operator may type a real identifier
into a rule's description while drafting, so the document is data the allowlist
exists to keep out of logs, not metadata to correlate on.

## Consequences

### Positive

- "What is enforced right now" is answerable from a URL, and "what was enforced
  on Tuesday" from the version history.
- The NFRs this project claims become demonstrable rather than asserted: the
  catalog shows detection is configuration-driven, the entity table shows
  thresholds and actions are configurable, and adding a rule from the catalog
  shows a new type needs no tokenizer or vault change.
- A risky edit is surfaced before publishing rather than discovered after.
- The playground makes policy design safe to iterate on, because the endpoint
  that accepts realistic text is the one that stores and logs nothing.

### Negative

- **A draft is a lock.** One draft per policy means a second operator cannot
  start editing until the first publishes or discards, and there is no way to
  see who holds it. Deliberate for an interview-scoped build; a real deployment
  would want ownership and a takeover path.
- **No approval workflow, scheduling, or rollback automation.** Publishing is
  immediate and one-way. Reverting means opening a draft, editing it back, and
  publishing again — which is honest, since it produces a new version rather
  than pretending the change never happened.
- **Unsaved draft edits are lost on reload.** They live in component state, and
  browser storage is deliberately not used for anything a caller typed
  (ADR-0019). The alternative — persisting to `localStorage` — would put policy
  text an operator may have pasted an identifier into somewhere it survives the
  tab.
- **Version numbers are per policy name and monotonic**, including numbers
  consumed by drafts that were discarded. A discarded draft leaves a gap in the
  sequence. Preferable to reusing a number that appeared in a log line.
- **The catalog's `CUSTOM_RECOGNIZER_TYPES` is a hand-maintained list.**
  Introspecting the recognizer registry would need a spaCy load on a cheap read.
  A new custom recognizer whose type is not added there is reported as built-in.

## Alternatives Considered

- **Edit the active policy in place, with an audit log of changes.** Simplest,
  and it makes the audit log the only record of what a version contained —
  reconstructing "the policy in force at 14:02" then means replaying a change
  feed, and any gap in that feed is unrecoverable. Rejected: the row is the
  record.
- **Copy-on-write with no explicit draft.** Every save creates a version.
  Removes the lock, and produces a version per keystroke-batch, so version
  numbers stop meaning "a decision someone made". Rejected.
- **Optimistic concurrency with an `updated_at` check instead of a draft
  index.** Handles the race, and only after both operators have done the work.
  The partial unique index refuses the second draft up front, which is a better
  moment to find out.
- **A frontend entity catalog.** No extra endpoint, and it drifts from the
  detector the first time either changes — offering a rule for a type the
  detector never emits, or omitting one it does. The omission is the dangerous
  direction, because an unconfigured type falls through to the fail-safe default
  rather than to the rule an operator thought they wrote. Rejected.
- **Return matched text from the playground.** Far more useful for designing a
  rule, and it turns the endpoint into the most reliable way to get sensitive
  values out of the gateway in a screenshot. Rejected; offsets are enough to
  highlight, and the browser already has the text it submitted.

## As Built

Verified by these tests. Where a promise is enforced by the schema rather than
by code, the test runs against a real database rather than a fake, because a
fake would agree with whatever the code did.

| Promise | Test |
|---|---|
| Published versions are immutable | `tests/unit/test_policy_lifecycle.py::TestPublishing::test_the_previous_version_is_unchanged_except_for_being_superseded` |
| Publishing creates a new version | `::TestPublishing::test_publishing_creates_a_new_active_version` |
| History accumulates, one active | `::TestPublishing::test_history_accumulates_rather_than_being_overwritten` |
| One draft at a time, enforced by the index | `::TestDraftCreation::test_only_one_draft_may_be_open_at_a_time` |
| A draft does not displace the live version | `::TestDraftCreation::test_a_draft_is_not_active_and_does_not_displace_the_live_version` |
| In-flight `PolicySnapshot` is unaffected | `::TestSnapshotIsolation::test_a_snapshot_taken_before_a_publish_is_unaffected_by_it` |
| Disabling protects rather than releases | `::TestDisabledRules::test_disabling_a_rule_protects_the_value_rather_than_releasing_it` |
| Pre-existing documents behave identically | `::TestDisabledRules::test_documents_written_before_enabled_existed_behave_identically` |
| Catalog is derived from the detector | `tests/unit/test_policy_authoring.py::TestDetectorCatalog::test_it_covers_exactly_what_the_detector_can_emit` |
| Catalog exposes no patterns | `::TestDetectorCatalog::test_the_catalog_discloses_no_patterns` |
| Validation rejects the documented cases | `::TestDraftValidation` (10 tests) |
| Validation echoes no document value | `::TestDraftValidation::test_problems_never_echo_a_value_from_the_document` |
| Risky changes warn without blocking | `::TestRiskWarnings::test_allowing_a_high_risk_entity_warns_without_blocking` |
| Diff computed from stored versions | `::TestDiff` (6 tests) |
| Publish re-validates rather than trusting the last save | `tests/unit/test_api_policies.py::TestPublishing::test_publishing_an_invalid_draft_is_refused` |
| Editing a published version is impossible | `::TestDraftLifecycle::test_editing_the_active_version_is_impossible` |
| A viewer cannot create or publish | `::TestAuthorization` (5 tests) |
| Playground falls back to the active version with no draft | `::TestPlayground::test_it_falls_back_to_the_active_version_when_no_draft_is_open` |
| Validation requires a draft and does not fall back | `::TestValidationAndDiff::test_validation_requires_a_draft_rather_than_checking_the_live_version` |
| Playground never calls a provider | `::TestPlayground::test_it_never_calls_a_provider` |
| Playground never writes a vault mapping | `::TestPlayground::test_it_never_writes_a_vault_mapping` |
| Playground returns no matched text | `::TestPlayground::test_it_returns_offsets_and_never_the_matched_text` |
| Playground input never reaches a log | `::TestPlayground::test_the_submitted_text_never_reaches_a_log_record` |
| Playground results are not cached | `::TestPlayground::test_results_are_not_cached` |
| A BLOCK says the provider would not be called | `::TestPlayground::test_a_blocking_action_says_the_provider_would_not_be_called` |
| Frontend keeps no entity catalog | `frontend/app/policies/[policyName]/page.test.tsx` — "adds an entity seeded from the detector catalog, not from a constant" |
| Publish requires explicit confirmation | `frontend/components/policy/PublishDialog.test.tsx` — "does not publish without an explicit click" |
| Risky change warns, does not block | `PublishDialog.test.tsx` — "warns without blocking, because the change may be legitimate" |
| Diff is fetched, not reconstructed | `frontend/app/policies/[policyName]/page.test.tsx` — "fetches the comparison from the backend rather than computing it" |
| No draft or playground text in browser storage | `frontend/lib/persistence.test.ts` |

Backend: `ruff format`, `ruff check`, `mypy app`, and 1737 tests.
Frontend: `lint`, `typecheck`, 158 tests, and `build`.
