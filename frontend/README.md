# Secure Chat Workspace

The operator-facing surface for the gateway: send a prompt or a document, and
see what was protected. Next.js App Router, React, TypeScript, Tailwind
(ADR-0017, ADR-0018).

Scope today is `architecture.md` §22.6 — the workspace and the Privacy
Inspector. The dashboard, session explorer, audit explorer, and policy manager
in §22.7–22.12 are **not** built; most of them need read APIs the backend does
not expose yet.

## Running it

```bash
cd frontend
cp .env.example .env.local          # set NEXT_PUBLIC_GATEWAY_ORIGIN if not :8000
npm install
npm run dev                         # http://localhost:3000
```

The gateway must allow the browser origin, which is off by default:

```bash
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

Then paste an API key with `chat:invoke`, `documents:write`, and
`documents:read`. `make compose-seed` prints one.

## What it does with your credential

Holds it in a module variable for the life of the tab, and loses it on reload.
Not local storage, not session storage, not a cookie — ADR-0019 and §22.15 both
forbid it, and the reload behaviour is the intended cost rather than a rough
edge to smooth over later.

## Two things the UI deliberately does not do

**It does not animate the pipeline.** §22.6 says the inspector shows "UI
progress states based on request lifecycle and returned metadata" and "must not
claim to receive private internal events that the API does not expose". The v1
API is synchronous and emits no per-stage events, so the inspector shows
`Gateway processing` and then the metadata that actually came back. The stage
list beside it is documentation of what the gateway does, not a progress bar —
showing "Tokenizing" because 300 ms elapsed would be theatre, and theatre in a
privacy inspector is a lie about the one thing the product asks to be trusted
on.

**It does not render markdown.** Model output is the one string on the page an
upstream party influences. React escapes by default and nothing here reaches
for `dangerouslySetInnerHTML`; §22.15 asks for markdown to stay off or be
sanitized against a strict allowlist, and off is the honest starting point.

## What the inspector can show

Counts, entity *type* names, policy actions, latency, request and session ids,
and the outbound attestation digest (ADR-0024). It cannot show matched values,
complete tokens, mapping payloads, or the provider request body — not by
convention but because those fields are absent from the types it accepts.

## Commands

```bash
npm run dev        # development server
npm run build      # production build
npm run lint       # eslint
npm run typecheck  # tsc --noEmit
```
