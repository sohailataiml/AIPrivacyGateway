# ADR-0035: AWS S3 Is the Object Store

- **Status:** Accepted
- **Date:** 2026-08-06
- **Supersedes:** [ADR-0027](0027-use-minio-locally.md)

## Context

ADR-0027 chose MinIO as the local object store and assumed a deployment would
point at S3. ADR-0034 made that switch explicit and checkable by naming the
provider in configuration. Both assumed the two would coexist: MinIO locally and
in CI, S3 in a deployment.

Running both has a cost that ADR-0027 accepted and ADR-0034 did not revisit. The
stack carries a fourth stateful service and a bucket-init container. CI starts a
MinIO container, waits on its health endpoint, and creates a bucket before any
test runs. Two credential sets exist that must never be confused. And the
property the arrangement was meant to buy — that the adapter is exercised against
a real S3 API — is only partly delivered: MinIO is S3-compatible, not S3, so IAM
evaluation, bucket policy, block-public-access, and virtual-host addressing were
never covered by the thing that claimed to cover them.

The decision to make is which single service the project targets.

## Decision

**AWS S3 is the object store.** MinIO is removed from the project: the Compose
service, the bucket-init container and its script, the dev-overlay port, and the
CI container are gone.

`ObjectStoreProvider` keeps two members, but they no longer name two supported
deployments:

- `aws` — the default and the backend the project runs.
- `compatible` — an escape hatch for pointing the adapter at another
  S3-compatible endpoint. It requires an endpoint and static credentials, which
  is what every such service needs. It is tested, because an untested escape
  hatch is a liability rather than an option, but it is not a supported
  deployment.

Nothing about the storage layer itself changes. `DocumentStore` is untouched,
`S3CompatibleDocumentStore` is untouched, object-key semantics are untouched,
and the document pipeline is untouched. This is a change of backend and of what
the repository ships around it.

Two consequences are handled rather than left implicit:

- **`DOCUMENTS_ENABLED` defaults to `false` in Compose.** There is no local
  object store any more, so a stack that enabled uploads unconditionally would
  fail readiness on any machine without AWS credentials — turning
  `docker compose up` from a working demo into a broken one. Chat, detection,
  tokenization, restoration, audit, and metrics all still run offline; the
  document path is opt-in and needs a bucket.
- **An empty credential variable means "unset".** Compose renders `${VAR:-}` as
  the empty string, as does every other templating layer asked for a value
  nobody supplied. Absent selects botocore's default credential chain; empty is
  a credential, so requests would be signed with nothing and rejected rather
  than falling back to a role. `Settings` normalises blank to `None`.

## Consequences

### Positive

- One object store, one credential set, one addressing style. The configuration
  a reviewer reads is the configuration production runs.
- The integration suite now exercises real S3: real IAM evaluation, real
  virtual-host addressing, real request signing, and a real
  block-public-access check. The unsigned-read test is meaningfully stronger
  against S3 than it was against a MinIO container the test itself configured.
- The local stack loses a stateful service, a init container, a volume, and a
  published port. CI loses a container start, a health-poll loop, and a bucket
  creation step.
- No second set of credentials that must never be mistaken for deployable ones.

### Negative

- **`docker compose up` no longer exercises the document path offline.** This is
  the real loss, and it was the property ADR-0027 existed to protect. Uploads
  now require an AWS account and a bucket. The rest of the gateway still runs
  with no cloud dependency.
- **The storage integration suite is gated on credentials.** Without
  `TEST_OBJECT_STORE_BUCKET` it skips, so a fork or a clone gets no coverage of
  the adapter. CI sets `REQUIRE_OBJECT_STORE_TESTS` from whether the bucket
  secret exists, so the suite fails loudly where it is supposed to run and skips
  honestly where it cannot — but a repository without the secret is running
  thirty-six fewer tests than one with it.
- **The tests cost money and touch a real bucket.** Small, but not zero, and a
  run interrupted mid-suite can leave objects behind.
- Contributors need AWS credentials to work on the storage adapter.

## Alternatives Considered

- **Keep MinIO for local and CI, S3 for deployment.** What ADR-0027 and ADR-0034
  already described, and defensible: it preserves the offline demo and gives CI
  free storage coverage. Rejected on the explicit instruction to remove MinIO
  from the runtime, and because the coverage it provides is weaker than it
  appears — the S3-specific behaviour most likely to break a deployment is
  exactly what MinIO does not implement.
- **Delete the storage integration suite outright.** Simplest reading of
  "remove MinIO entirely", and it would leave the adapter verified only against
  an in-memory dictionary that cannot fail a 5 MiB part rule or sign a request.
  Four of this project's defects were visible only from a running container.
  Rejected: the suite was retargeted, not deleted.
- **Keep `DOCUMENTS_ENABLED=true` in Compose.** Honest about the new
  requirement, and it makes the default stack fail readiness on a laptop.
  Rejected in favour of an opt-in switch with the command to flip it documented
  in the Compose file itself.
- **LocalStack as the S3 stand-in.** Reintroduces a local emulator with the same
  compatibility gap MinIO had, plus more surface. Rejected for the reasons
  ADR-0027 already gave.
