# ADR-0028: Use Spawned Process Isolation for Document Extraction

- **Status:** Accepted
- **Date:** 2026-08-05

## Context

Extraction is the first stage that actually parses an uploaded file. Phase 1
(ADR-0020) checked eight magic bytes and stored whatever followed, deliberately:
deciding whether a PDF really parses means parsing it. So every hostile document
the gateway will ever receive arrives, intact, at this stage.

[threat-model.md](../threat-model.md) already committed to what that requires —
it says the exposure from malicious document content "begins when extraction
parses it, which is where a sandboxed, bounded extraction path becomes
load-bearing rather than merely planned." This ADR is that path.

Three failure modes matter, and none of them is a Python exception:

- **A parser that does not terminate.** A crafted PDF with a pathological
  object graph can send a parser into work that never finishes.
- **A parser that allocates without bound.** Memory exhaustion is a
  process-level event; the OOM killer does not choose the guilty request.
- **A native crash.** `lxml` is a C extension, and a segfault ends every
  in-flight request, not only the one holding the bad file.

Python threads cannot be killed, cannot be memory-limited, and share a fate with
the interpreter. A thread pool would bound concurrency and nothing else.

`concurrent.futures.ProcessPoolExecutor` solves the crash and memory cases but
not cancellation: a future cannot be cancelled once it has started running, so a
timeout on it stops the parent waiting while the child keeps consuming a core
indefinitely. That is worse than no timeout, because it looks like one.

## Decision

Run each extraction in its **own spawned subprocess**, with:

- **one worker process per document**, created for that document and reaped
  after it;
- **`asyncio.Semaphore`-bounded concurrency**, so the number of simultaneous
  workers is capped by configuration rather than by traffic;
- **timeout-driven termination** — the parent waits on the pipe for a bounded
  interval, then `terminate()`s the child and, if needed, `kill()`s it;
- **only bytes and safe reason codes across the boundary**: the parent sends
  the document bytes, the content type, and a character limit; the child returns
  either a list of page strings or a short reason string.

The `spawn` start method is used on every platform, including Linux where `fork`
is the default.

## Consequences

### Positive

- A hung parser costs one worker and one request, not the gateway.
- A native crash or an OOM kill is contained to the child; the parent observes
  EOF on the pipe and fails closed with `DOCUMENT_EXTRACTION_FAILED`.
- The timeout is real. `terminate()` genuinely ends a process, so the budget in
  `EXTRACTION_TIMEOUT_SECONDS` is enforced rather than hoped for.
- `spawn` gives the child a fresh interpreter. It inherits no key ring, no
  database pool, no Redis connection, and no audit queue — the process running a
  parser over an attacker's file holds nothing worth stealing. A `fork`ed child
  would inherit all of it.
- Exceptions never cross the boundary, so a traceback — whose frames hold the
  document — is never pickled into the parent.

### Negative

- Process startup per document. `spawn` re-imports the interpreter and the
  worker module, which costs roughly 100–300 ms. That is small next to parsing a
  file large enough to be worth worrying about, and it is paid per document
  rather than per request.
- The document bytes are pickled to the child, so a large upload is briefly
  resident twice.
- Extraction cannot stream. A PDF cross-reference table sits at the end of the
  file and points backwards, so the parser needs the whole document; the bytes
  are buffered in `DocumentProcessor` under the existing `MAX_DOCUMENT_BYTES`
  bound. This is the one place in the document path that does not stream, and it
  is a further reason the parse happens elsewhere.

## Alternatives Considered

- **Thread pool with a semaphore.** Simplest, keeps plaintext in one process,
  and survives none of the three failure modes above. Rejected.
- **`ProcessPoolExecutor`.** Reuses workers and avoids per-document startup, but
  its futures cannot be cancelled once running, so its timeout abandons rather
  than ends the work. Killing the pool and rebuilding it on every timeout was
  considered and rejected as more machinery for a worse guarantee. Rejected.
- **`fork` instead of `spawn`.** Cheaper startup, and it hands the parser a copy
  of the parent's memory including key material. Rejected.
- **An external sandbox (seccomp, gVisor, a container per extraction).**
  Stronger isolation and disproportionate for this system's threat model and
  deployment story. Revisit if extraction ever runs untrusted plugins.

## Implementation Constraints

- Worker functions are module-level and picklable; a closure or bound method
  cannot cross a `spawn` boundary.
- The parent closes its copy of the pipe's write end immediately, or a dead
  child looks like a hung one instead of reporting EOF.
- The child is reaped on every exit path, including the timeout and error paths.
  A leaked worker is a leaked core.
- The extracted-character limit is enforced **inside** the child while
  accumulating. Checking on return would mean the allocation the limit exists to
  prevent had already happened.
- Third-party parser loggers are silenced inside the child as well as the
  parent: a spawned interpreter has none of the parent's logging configuration.
- A zero or negative worker count, timeout, or character limit is refused at
  construction, so an unbounded configuration is a startup failure rather than a
  runtime surprise.

## As Built (Phase 2)

`app/documents/extraction/runner.py`. `SubprocessExtractionRunner` is the only
runner used outside tests. `InlineExtractionRunner` exists for tests of
*callers* and provides no isolation whatsoever, which is why the isolation suite
in `tests/security/test_document_extraction_isolation.py` never uses it.

Extraction libraries are **pypdf** (BSD-3) and **python-docx** (MIT), both pure
Python and both compatible with this project's Apache-2.0 licence. PyMuPDF is
faster and is AGPL, which this project cannot distribute.
