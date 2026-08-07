# ADR-0034: Name the Object Store Provider Instead of Inferring It

- **Status:** Accepted, amended by [ADR-0035](0035-aws-s3-is-the-object-store.md)
- **Date:** 2026-08-06

> **Amended the same day.** ADR-0035 removed MinIO from the project. The
> mechanism below is unchanged and still in force -- the provider is named,
> not inferred, and production refuses incoherent combinations. What changed
> is the membership and the default: `minio` became `compatible`, and the
> default flipped from `minio` to `aws`. Read the table below with those two
> substitutions.

## Context

ADR-0027 chose MinIO for the local stack and asserted that swapping it for AWS
S3 is a configuration change, not a code change. That held — `S3CompatibleDocumentStore`
uses only `PutObject`, multipart, `GetObject`, `DeleteObject`, and `HeadBucket`,
which both services implement identically — but the configuration itself was
never made to say which service it meant.

Three variables carried the distinction implicitly, and they disagreed:

- `OBJECT_STORE_ENDPOINT_URL` documented `None` as "real AWS S3".
- `OBJECT_STORE_USE_PATH_STYLE` defaulted to `true`, which is MinIO's
  convention and the one AWS deprecated.
- `OBJECT_STORE_ACCESS_KEY_ID` and `OBJECT_STORE_SECRET_ACCESS_KEY` were
  *required* in production.

So the shipped defaults described a service that does not exist: AWS addressing
with MinIO's addressing style. Worse, each variable was independently valid, so
the combinations that are nonsense were unreachable by any check:

- **MinIO with no endpoint.** Does not fail. botocore resolves real AWS S3, and
  the gateway attempts to store documents in an account nobody intended, using
  MinIO credentials. `head_bucket` is the readiness probe, and against a bucket
  that happens to exist it passes.
- **AWS with a leftover endpoint** from a copied `.env`. Production traffic goes
  to a host that is not there.

The credential requirement is a separate problem. On AWS the correct posture is
the instance or task role: botocore's default credential chain issues
short-lived credentials that rotate themselves. Demanding a static key pair
forced every hosted deployment to hold a long-lived secret it never needed.

## Decision

Add `OBJECT_STORE_PROVIDER`, an enum of `minio` and `aws`, defaulting to
`minio`.

It selects **configuration, not an implementation**. There is still exactly one
`S3CompatibleDocumentStore`, it still has no provider field, and it still cannot
ask which service it is talking to. `Settings` resolves the provider down to
plain values — a boolean for addressing style, an optional endpoint, optional
credentials — and the store receives those.

The provider drives three things:

| | `minio` | `aws` |
|---|---|---|
| Endpoint | required | must be absent |
| Addressing | path | virtual-host |
| Credentials | required | optional; unset selects the default chain |

`OBJECT_STORE_USE_PATH_STYLE` becomes `bool | None`. Unset, it follows the
provider's convention; set, it overrides. The override is kept because an
S3-compatible service behind a VPC endpoint can need path style while still
being AWS, and a provider enum that overruled the operator would make that
deployment unreachable.

Production refuses the incoherent combinations at startup.

## Consequences

### Positive

- The two quiet misconfigurations above become startup failures naming the
  variable, at the point where the operator's intent is still stated.
- AWS deployments can use a task or instance role, so the hosted path holds no
  long-lived object-store secret.
- The common case needs fewer variables, not more: addressing style is now
  derived, so a correct MinIO or AWS configuration never sets it.
- The store keeps no knowledge of either vendor, so there is nowhere for
  provider-specific behaviour to accumulate and drift.

### Negative

- **A breaking configuration change.** A deployment that relied on
  `OBJECT_STORE_ENDPOINT_URL` being unset to mean AWS must now set
  `OBJECT_STORE_PROVIDER=aws`, or it will be refused for a missing endpoint.
  This is deliberate: that deployment was also running with path-style
  addressing it did not ask for.
- One more variable to set, and a default (`minio`) that favours the local
  stack over the hosted one.
- The AWS path is verified by configuration tests only. MinIO is exercised
  against a real server in the object-store integration suite; there is no
  equivalent for S3, so a first deployment against real S3 still needs its own
  verification, as ADR-0027 already noted.

  *Since amended:* ADR-0035 retargeted that suite at real S3
  (`tests/integration/test_documents_s3.py`). The gap named here is closed in
  principle — but only where a bucket is configured, and it has not yet been
  run against one.

## Alternatives Considered

- **Infer the provider from whether an endpoint is set.** No new variable, and
  it reintroduces exactly what this ADR removes: intent stays implicit, and
  "MinIO with a forgotten endpoint" remains indistinguishable from "AWS",
  which is the more damaging of the two failures. Rejected.
- **Two store classes behind the `DocumentStore` Protocol.** The Protocol would
  absorb it cleanly, but there is no provider-specific behaviour for the second
  class to hold — the gateway encrypts documents itself, so it needs no SSE-KMS,
  and it addresses objects by key, so it needs no bucket policy or admin API.
  Two classes over an empty difference is duplicated storage logic waiting to
  drift. Rejected.
- **Keep requiring static credentials on AWS.** Simpler validation, and it
  forces every hosted deployment into weaker secret handling than the platform
  offers. Rejected.
- **Add SSE-KMS configuration for AWS.** Documents are already sealed with
  per-document AES-256-GCM keys before they reach the store (ADR-0020), so
  server-side encryption is defence in depth at most. Deferred until a
  compliance requirement actually asks for it, rather than built speculatively.
