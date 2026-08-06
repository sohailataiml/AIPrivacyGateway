# ADR-0027: Use MinIO as the Local S3-Compatible Object Store

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

ADR-0020 puts uploaded documents in S3-compatible object storage with
application-layer encryption. It names MinIO for the Compose and interview
environment but does not settle what "the local object store" is, and the
document pipeline is about to be built against it.

The local choice matters more than it looks. The Compose stack is the artifact
reviewers run and the one every integration test targets, so whatever sits there
defines what "works" means for the document path. Three constraints bear on it:

- **No cloud credentials.** `docker compose up` must work offline, on a laptop,
  with no account anywhere. The stack already holds to this — `DEFAULT_PROVIDER`
  is `mock` specifically so bringing it up cannot make a paid API call.
- **A real S3 API, not a simulation.** The gateway's storage code is the thing
  under test. Something that merely resembles S3 lets an incompatibility survive
  until deployment, which is the failure mode the container defects in this
  project's history all shared.
- **Production is not this.** A deployment uses S3 or another managed
  S3-compatible service. Anything local is a stand-in, and the code must not be
  able to tell the difference.

## Decision

Use **MinIO** as the local S3-compatible object store, as a Compose service
alongside PostgreSQL and Redis.

The application talks to it through the S3 API only, configured by endpoint,
credentials, and bucket. Swapping MinIO for S3 is a configuration change, not a
code change.

## Consequences

### Positive

- The document path can be exercised end to end offline, with no cloud account
  and no credentials to leak into a repository.
- MinIO implements the real S3 API, so the client, the request signing, and the
  error surface exercised locally are the ones used in production.
- Object storage becomes a declared dependency of the stack, with a health check
  and a readiness contribution, rather than something mocked in tests and absent
  from the artifact.
- Integration tests get a disposable, resettable store, in the same shape as the
  disposable PostgreSQL and Redis the suite already expects.

### Negative

- A fourth stateful service in the local stack: more startup time, more memory,
  another health check, another thing that can fail on a laptop.
- MinIO is S3-compatible, not S3. Coverage of IAM behaviour, bucket policy
  evaluation, versioning semantics, and consistency edges is partial, so a
  deployment against real S3 still needs its own verification.
- Local throwaway credentials in the Compose file are one more set of values
  that must never be mistaken for deployable ones.

## Alternatives Considered

- **Real S3 with a test bucket.** Highest fidelity, and requires an account,
  network access, and credentials to run the stack at all. Rejected: it breaks
  the offline-by-default property and puts credentials in the demo path.
- **LocalStack.** Emulates far more of AWS than this needs; heavier, and the
  breadth is unused because the gateway wants one service. Rejected as
  disproportionate.
- **A filesystem-backed fake behind the storage Protocol.** Cheapest, and it
  tests the gateway against the gateway's own idea of S3. That is precisely the
  gap in which defects 9 and 10 lived — the code was consistent with itself and
  the artifact did not work. Retained as a *unit-test* fake, rejected as the
  local stack.
- **Reusing PostgreSQL for bytes.** Rejected by ADR-0020.

## Implementation Constraints

- MinIO is a Compose service with a health check, and the gateway's readiness
  check reports object storage the way it already reports PostgreSQL and Redis.
  A store that cannot be reached fails the request closed, per ADR-0008.
- The application depends on the S3 API and never on MinIO-specific behaviour,
  admin endpoints, or the MinIO console. Endpoint, region, credentials, bucket,
  and path-style addressing are configuration.
- Credentials come from settings, never from literals in application code. The
  Compose values are throwaway and are marked as such alongside the existing
  local keys, which `Settings` already refuses to accept under `APP_ENV=production`.
- Bucket creation and any lifecycle rules are part of bringing the stack up —
  a documented, repeatable step, not a manual click in a console.
- Encryption remains the gateway's job. MinIO's own server-side encryption is
  defence in depth at most; objects are sealed before they are sent (ADR-0020)
  and bound to tenant, user, and document (ADR-0021).
- Integration tests targeting object storage skip when their endpoint variable
  is unset, matching how the PostgreSQL and Redis integration tests already
  behave, so the default unit run stays dependency-free.
- Nothing about the local stack's convenience reaches production configuration:
  no default endpoint, no default credentials, no implicit bucket.
