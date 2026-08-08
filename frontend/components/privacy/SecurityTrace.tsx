"use client";

import { protectedSpanCount } from "@/components/privacy/Outbound";
import type { PrivacySummary, ProtectedPreview } from "@/lib/gateway";

/**
 * The security lifecycle, rendered between the prompt and the answer.
 *
 * The Privacy Inspector already reported all of this, and reported it well --
 * but it reported it in a side panel, below the fold, disconnected from the turn
 * it described. A reader had to hold the prompt in their head, scroll, and join
 * the two up themselves. This puts the middle of the story where the story is:
 * what you typed, what actually went upstream, what came back.
 *
 * **The connectors are labels, not arrows.** A stage whose meaning depends on a
 * glyph is unreadable to a screen reader and looks like a slide deck to
 * everyone else. Each connector is a short rule with a text label, so the
 * sequence survives being read aloud, being printed, and being viewed with
 * colour stripped out.
 *
 * **Nothing here is computed by the browser.** The masked text arrives already
 * masked (`app/pipeline/preview.py`), the entity actions are derived from the
 * protected text rather than from policy intent, and the scan verdict is the
 * backend's. This component chooses layout and wording; it never derives a
 * security claim. That distinction is why the wording below is scoped to
 * *detected* values -- a detector false negative is a documented residual risk,
 * so "no sensitive data reached the provider" would be a claim this page has no
 * standing to make.
 */

export interface Blocked {
  code: string;
  message: string;
}

export interface SecurityTraceProps {
  /**
   * Null on a refusal. The gateway returns no privacy summary when it blocks,
   * so a zeroed stand-in would render "0 sensitive values transformed" -- a
   * count the backend never produced, and the opposite of what happened.
   */
  summary: PrivacySummary | null;
  /** Masked server-side. Null when the deployment has not enabled the preview. */
  preview: ProtectedPreview | null;
  provider: string | null;
  /** Set when the gateway refused. The provider stage is then never rendered. */
  blocked: Blocked | null;
}

const POLICY_VIOLATION = "POLICY_VIOLATION";

function Connector({ label, detail }: { label: string; detail?: string }) {
  return (
    <div className="flex items-stretch gap-3 py-1 pl-4" aria-hidden={false}>
      <div className="ml-1 w-px bg-edge" />
      <div className="py-1">
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted">{label}</p>
        {detail ? <p className="mt-0.5 text-[11px] text-muted">{detail}</p> : null}
      </div>
    </div>
  );
}

export function SecurityTrace({ summary, preview, provider, blocked }: SecurityTraceProps) {
  const spans = summary === null ? null : protectedSpanCount(summary);
  const transformed =
    spans === null ? undefined : `${spans} sensitive value${spans === 1 ? "" : "s"} transformed`;

  if (blocked !== null) {
    return (
      <div data-testid="security-trace">
        <Connector label="Secure AI Gateway" detail={transformed} />
        <section
          aria-labelledby="blocked-stage-heading"
          className="rounded-lg border border-danger/40 bg-danger/5 px-4 py-3"
          data-testid="blocked-stage"
        >
          <h3
            id="blocked-stage-heading"
            className="text-[11px] font-semibold uppercase tracking-wide text-danger"
          >
            {blocked.code === POLICY_VIOLATION ? "Policy blocked request" : "Request refused"}
          </h3>
          <p className="mt-1.5 text-sm leading-relaxed text-ink">{blocked.message}</p>
          {/* The load-bearing line. Stated as text, not implied by the absence
              of a provider card below it. */}
          <p
            className="mt-2 inline-block rounded border border-danger/40 px-2 py-0.5 font-mono
                       text-[10px] font-semibold uppercase tracking-wide text-danger"
            data-testid="not-sent"
          >
            Not sent to provider
          </p>
        </section>
      </div>
    );
  }

  return (
    <div data-testid="security-trace">
      <Connector label="Secure AI Gateway" detail={transformed} />

      <section
        aria-labelledby="protected-stage-heading"
        className="rounded-lg border border-protect/30 bg-protect/5 px-4 py-3"
        data-testid="protected-stage"
      >
        <h3
          id="protected-stage-heading"
          className="text-[11px] font-semibold uppercase tracking-wide text-protect"
        >
          Protected payload sent to LLM
        </h3>

        {preview && preview.entity_summary.length > 0 ? (
          <ul className="mt-2 space-y-0.5" data-testid="preview-entities">
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
            <h4 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted">
              Provider-safe payload preview
            </h4>
            {/* Already masked when it arrived. This component receives no token
                to hide, which is the only reason rendering it is safe. */}
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

        <p
          className="mt-2.5 flex items-center gap-1.5 text-[11px] font-semibold text-protect"
          data-testid="outbound-scan"
        >
          <span aria-hidden>✓</span>
          <span>Outbound scan passed</span>
        </p>

        <p className="mt-1.5 text-[11px] leading-relaxed text-muted">
          {preview?.text
            ? "Sensitive values were replaced before transmission. The provider received opaque gateway tokens in these positions; the masks above are this browser's view, and the identifiers behind them never leave the gateway."
            : "Sensitive values were replaced before transmission. The payload itself is not returned by this deployment, so only what was done to it is shown."}
        </p>
      </section>

      <Connector label={provider === "mock" ? "Mock provider" : (provider ?? "Provider")} />
    </div>
  );
}
