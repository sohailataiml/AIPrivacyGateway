"use client";

import type { PrivacySummary } from "@/lib/gateway";
import { GATEWAY_STAGES, STAGE_LABELS, type InspectorStage } from "@/lib/inspector";

/**
 * The Privacy Inspector.
 *
 * architecture.md section 22.6 lists what may appear here and what may not.
 * The "may not" list is the interesting one: matched original values, complete
 * gateway tokens, encrypted mapping payloads, provider request bodies. None of
 * those are reachable from this component, because none of them are on the
 * types it accepts -- `PrivacySummary` is counts and type names, and the
 * attestation is a digest.
 *
 * That is deliberate. A rule enforced by "the developer remembers" is a rule
 * with a shelf life; a rule enforced by the props not existing is not.
 */

export interface InspectorProps {
  stage: InspectorStage;
  summary: PrivacySummary | null;
  requestId: string | null;
  sessionId: string | null;
  policyVersion: number | null;
  attestation: string | null;
  elapsedMs: number | null;
  refusalCode: string | null;
}

const ACTION_ROWS: ReadonlyArray<[keyof PrivacySummary, string]> = [
  ["tokenized", "Tokenized"],
  ["redacted", "Redacted"],
  ["pseudonymized", "Pseudonymized"],
  ["allowed", "Allowed"],
  ["restored", "Restored"],
  ["unknown_tokens", "Unknown tokens"],
];

export function Inspector(props: InspectorProps) {
  const { stage, summary, requestId, sessionId, attestation, elapsedMs, refusalCode } = props;
  const busy = stage === "uploading" || stage === "in_flight";

  return (
    <aside className="panel flex h-full flex-col gap-5 p-5" aria-label="Privacy Inspector">
      <header>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-muted">
          Privacy Inspector
        </h2>
        <p
          className="mt-1 flex items-center gap-2 text-lg"
          aria-live="polite"
          data-testid="inspector-stage"
        >
          {busy ? (
            <span className="h-2 w-2 animate-pulse rounded-full bg-accent" aria-hidden />
          ) : null}
          <span className={stage === "refused" ? "text-danger" : "text-ink"}>
            {STAGE_LABELS[stage]}
          </span>
        </p>
        {refusalCode ? (
          <p className="mt-1 font-mono text-xs text-danger">{refusalCode}</p>
        ) : null}
      </header>

      <section aria-label="Gateway stages">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
          What the gateway does
        </h3>
        {/* Not a progress bar. The v1 API is synchronous and emits no per-stage
            events, so highlighting one of these would be a claim the client
            cannot support. */}
        <ol className="mt-2 space-y-1 text-xs text-muted">
          {GATEWAY_STAGES.map((label) => (
            <li key={label} className="flex gap-2">
              <span aria-hidden>·</span>
              {label}
            </li>
          ))}
        </ol>
      </section>

      {summary ? (
        <>
          <section aria-label="Detections by entity type">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
              Detected ({summary.detected})
            </h3>
            {Object.keys(summary.entity_types).length === 0 ? (
              <p className="mt-2 text-xs text-muted">Nothing sensitive was found.</p>
            ) : (
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {Object.entries(summary.entity_types)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([type, count]) => (
                    <li
                      key={type}
                      className="rounded border border-edge px-2 py-0.5 font-mono text-[11px] text-protect"
                    >
                      {type} × {count}
                    </li>
                  ))}
              </ul>
            )}
          </section>

          <section aria-label="Policy actions">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
              Actions
            </h3>
            <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              {ACTION_ROWS.map(([key, label]) => (
                <div key={key} className="contents">
                  <dt className="text-muted">{label}</dt>
                  <dd className="text-right font-mono text-ink">{String(summary[key])}</dd>
                </div>
              ))}
            </dl>
          </section>
        </>
      ) : null}

      <section aria-label="Request metadata" className="mt-auto">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Request</h3>
        <dl className="mt-2 space-y-1 text-xs">
          <Meta label="Request id" value={requestId} mono />
          <Meta label="Session" value={sessionId} mono />
          <Meta
            label="Policy version"
            value={props.policyVersion === null ? null : String(props.policyVersion)}
          />
          <Meta label="Round trip" value={elapsedMs === null ? null : `${elapsedMs} ms`} />
        </dl>
        {attestation ? (
          <div className="mt-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
              Outbound attestation
            </h3>
            {/* A keyed digest of the exact bytes sent upstream (ADR-0024).
                Shown because it is evidence and discloses nothing. */}
            <p className="mt-1 break-all font-mono text-[10px] leading-relaxed text-muted">
              {attestation}
            </p>
          </div>
        ) : null}
      </section>
    </aside>
  );
}

function Meta({ label, value, mono }: { label: string; value: string | null; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-muted">{label}</dt>
      <dd className={`truncate text-right ${mono ? "font-mono text-[11px]" : ""} text-ink`}>
        {value ?? "—"}
      </dd>
    </div>
  );
}
