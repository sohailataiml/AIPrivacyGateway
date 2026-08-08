"use client";

import type { PrivacySummary, ProtectedPreview as ProtectedPreviewData } from "@/lib/gateway";

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
 * **The payload preview arrives already masked.** `⟦PERSON:••••⟧` is what the
 * server sends; the identifier that names a vault mapping is replaced before it
 * leaves the gateway. This component never receives a full token and so is
 * never trusted to hide one -- a client asked to mask would still hold the token
 * in memory, in the network tab, and in any error report the page produced.
 *
 * The preview is absent unless the deployment sets `PROTECTED_PREVIEW_ENABLED`,
 * because it is still a rendering of the provider request body, which
 * architecture.md 22.6 otherwise keeps out of this panel. When it is absent the
 * section falls back to counts and the scan outcome, which is what it showed
 * before the preview existed.
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
  preview,
}: {
  summary: PrivacySummary;
  scanPassed: boolean;
  preview?: ProtectedPreviewData | null;
}) {
  const spans = protectedSpanCount(summary);

  return (
    <section aria-labelledby="payload-heading" data-testid="protected-payload">
      <h3
        id="payload-heading"
        className="text-[11px] font-semibold uppercase tracking-wide text-muted"
      >
        Protected payload sent to LLM
      </h3>

      <p className="mt-1.5 text-xs text-ink">
        <span className="font-mono tabular-nums">{spans}</span> sensitive value
        {spans === 1 ? "" : "s"} transformed
      </p>

      {preview && preview.entity_summary.length > 0 ? (
        <ul className="mt-2 space-y-1" data-testid="preview-entities">
          {preview.entity_summary.map((item) => (
            <li
              key={`${item.entity_type}-${item.action}`}
              className="flex items-baseline justify-between gap-3 text-[11px]"
            >
              <span className="font-mono text-ink">
                {item.entity_type} <span className="text-muted">×&nbsp;{item.count}</span>
              </span>
              <span className="font-mono uppercase tracking-wide text-protect">
                {item.action}d
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      {preview?.text ? (
        <div className="mt-3">
          <h4 className="text-[10px] uppercase tracking-wide text-muted">Preview</h4>
          {/* Plain text, pre-wrapped. The masking already happened on the
              server -- this component receives no token to hide, which is why
              it is safe to render at all. */}
          <p
            className="mt-1 whitespace-pre-wrap break-words rounded border border-edge bg-surface
                       px-2.5 py-2 font-mono text-[11px] leading-relaxed text-ink"
            data-testid="preview-text"
          >
            {preview.text}
          </p>
          {preview.truncated ? (
            <p className="mt-1 text-[10px] text-muted">Shortened for display.</p>
          ) : null}
        </div>
      ) : null}

      <p className="mt-2.5 flex items-baseline justify-between gap-3 text-xs">
        <span className="text-muted">Outbound scan</span>
        <span
          className={`font-mono text-[11px] font-semibold ${scanPassed ? "text-protect" : "text-muted"}`}
          data-testid="outbound-scan"
        >
          {scanPassed ? "PASSED" : "—"}
        </span>
      </p>

      <p className="mt-1.5 text-[11px] leading-relaxed text-muted">
        {preview?.text
          ? "Values were replaced before transmission. The provider saw the text above; the identifiers behind each mask never leave the gateway."
          : "The payload itself is never stored or returned, so it cannot be shown here — only what was done to it."}
      </p>
    </section>
  );
}
