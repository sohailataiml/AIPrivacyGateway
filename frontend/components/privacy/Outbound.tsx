"use client";

import type { PrivacySummary } from "@/lib/gateway";

/**
 * What left the gateway, described without disclosing any of it.
 *
 * Two sections, and the wording of both is load-bearing.
 *
 * **Attestation says ATTESTED, not VERIFIED.** The API returns a keyed digest
 * of the exact bytes sent upstream (ADR-0024). Verifying it requires the audit
 * HMAC key, which lives on the server and must never reach a browser -- so this
 * client cannot check it and must not imply that it did. "Attested" is the true
 * claim: the gateway produced this digest for this request. A green VERIFIED
 * tick rendered by code that verified nothing is precisely the kind of security
 * theatre this panel exists to avoid.
 *
 * **The payload preview is metadata.** There is no safe preview of a protected
 * payload to show: the canonical outbound bytes are never persisted and never
 * returned (that is the point), and partial tokens are still fragments of a
 * reversible identifier. So this section counts spans and states the outcome,
 * and shows no payload at all.
 */

const DIGEST_PREFIX_CHARS = 12;

export function Attestation({ digest }: { digest: string }) {
  return (
    <section aria-labelledby="attestation-heading">
      <h3
        id="attestation-heading"
        className="text-[11px] font-semibold uppercase tracking-wide text-muted"
      >
        Outbound attestation
      </h3>
      <p className="mt-1.5 flex items-center gap-1.5 text-xs font-semibold text-protect">
        <span aria-hidden>✓</span>
        <span>ATTESTED</span>
      </p>
      <dl className="mt-2 space-y-1">
        <div className="grid grid-cols-[5.5rem_1fr] gap-2">
          <dt className="text-[11px] text-muted">Digest</dt>
          <dd
            className="min-w-0 break-all font-mono text-[10px] leading-relaxed text-ink"
            title={digest}
            data-testid="attestation-digest"
          >
            {digest.slice(0, DIGEST_PREFIX_CHARS)}…
          </dd>
        </div>
      </dl>
      <p className="mt-1.5 text-[11px] leading-relaxed text-muted">
        Keyed digest of the protected outbound request. Verifying it requires the
        server-side audit key, so it is evidence to check against the audit log,
        not something this page can confirm.
      </p>
    </section>
  );
}

/**
 * Count the values that were altered before transmission.
 *
 * Deliberately not `detected`: a detected entity the policy chose to allow was
 * sent as written, and counting it as protected would overstate what happened.
 */
export function protectedSpanCount(summary: PrivacySummary): number {
  return summary.tokenized + summary.redacted + summary.pseudonymized;
}

export function ProtectedPayload({
  summary,
  scanPassed,
}: {
  summary: PrivacySummary;
  scanPassed: boolean;
}) {
  const spans = protectedSpanCount(summary);

  return (
    <section aria-labelledby="payload-heading" data-testid="protected-payload">
      <h3
        id="payload-heading"
        className="text-[11px] font-semibold uppercase tracking-wide text-muted"
      >
        Protected payload sent to provider
      </h3>
      <ul className="mt-2 space-y-1 text-xs">
        <li className="flex items-baseline justify-between gap-3">
          <span className="text-muted">Provider-safe payload</span>
          <span className="font-mono text-[11px] tabular-nums text-ink">
            {spans} span{spans === 1 ? "" : "s"} protected
          </span>
        </li>
        {summary.allowed > 0 ? (
          <li className="flex items-baseline justify-between gap-3">
            <span className="text-muted">Allowed by policy</span>
            <span className="font-mono text-[11px] tabular-nums text-ink">{summary.allowed}</span>
          </li>
        ) : null}
        <li className="flex items-baseline justify-between gap-3">
          <span className="text-muted">Outbound scan</span>
          <span
            className={`font-mono text-[11px] font-semibold ${scanPassed ? "text-protect" : "text-muted"}`}
            data-testid="outbound-scan"
          >
            {scanPassed ? "PASSED" : "—"}
          </span>
        </li>
      </ul>
      <p className="mt-1.5 text-[11px] leading-relaxed text-muted">
        The payload itself is never stored or returned, so it cannot be shown
        here — only what was done to it.
      </p>
    </section>
  );
}
