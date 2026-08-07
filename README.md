# Secure AI Gateway Interview Specification

Read in this order:

1. `architecture.md`
2. `implementation.md`
3. `PROGRESS.md` — what is actually built, and the defects found building it
4. `docs/adr/README.md`
5. `docs/observability.md` — metrics catalog, cardinality rules, alert recommendations
6. `docs/frontend-architecture.md`
7. `docs/ui-wireframes.md`
8. `docs/demo-script.md`
9. `docs/interview-talk-track.md`

The secure-context pipeline is the core security capability. The frontend is an
enterprise presentation and operations layer over the gateway.

## Surfaces

| Route | What it is for |
|---|---|
| `/chat` | Send prompts and documents through the gateway, and inspect what was protected |
| `/policies` | What the gateway detects and what it does about it |
| `/policies/{name}` | Entity rules, version history, and the draft-and-publish workflow |
| `/policies/{name}/test` | Run text through a policy without calling a provider |

Policy versions are immutable once published; edits happen on a draft
([ADR-0037](docs/adr/0037-immutable-versioned-policies.md)). A request already in
flight keeps the `PolicySnapshot` it started with, so publishing never changes
the rules a half-processed request is being protected by.

