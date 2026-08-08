"use client";

import { DocumentCard, type DocumentStatus } from "@/components/documents/DocumentCard";
import { BlockedNotice } from "@/components/privacy/Blocked";
import { DiagnosticRow, EntityBadges, MetricCard } from "@/components/privacy/Metrics";
import { Attestation, ProtectedPayload } from "@/components/privacy/Outbound";
import { Pipeline } from "@/components/privacy/Pipeline";
import type { PrivacySummary, ProtectedPreview } from "@/lib/gateway";
import { pipelineFor, STAGE_LABELS, type InspectorStage } from "@/lib/inspector";

/**
 * The Privacy Inspector.
 *
 * architecture.md section 22.6 lists what may appear here and what may not.
 * The "may not" list is the interesting one: matched original values, complete
 * gateway tokens, encrypted mapping payloads. None of those are reachable from
 * this component, because none of them are on the types it accepts --
 * `PrivacySummary` is counts and type names, and the attestation is a digest.
 *
 * That is deliberate. A rule enforced by "the developer remembers" is a rule
 * with a shelf life; a rule enforced by the props not existing is not.
 *
 * `preview` is the one narrowed exception, and it is narrowed on the server:
 * it holds a rendering of the provider request body with every token identifier
 * already replaced, so this component still has no way to obtain one. It is
 * absent unless the deployment opts in.
 *
 * Ordering follows what a reader needs in the order they need it: the outcome,
 * then the pipeline that produced it, then what was found, then what was sent,
 * then the identifiers they would quote in a bug report.
 */

export interface InspectorProps {
  stage: InspectorStage;
  summary: PrivacySummary | null;
  requestId: string | null;
  sessionId: string | null;
  /** Not returned by any v1 response. Renders as an em dash, honestly. */
  policyVersion: number | null;
  attestation: string | null;
  elapsedMs: number | null;
  refusalCode: string | null;
  refusalMessage: string | null;
  provider: string | null;
  document: DocumentStatus | null;
  /** Masked, server-side. Absent unless the deployment enables it. */
  preview: ProtectedPreview | null;
}

function formatLatency(ms: number | null): string | null {
  if (ms === null) return null;
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function Inspector(props: InspectorProps) {
  const {
    stage,
    summary,
    requestId,
    sessionId,
    attestation,
    elapsedMs,
    refusalCode,
    refusalMessage,
    provider,
    document,
    preview,
  } = props;

  const busy = stage === "uploading" || stage === "in_flight";
  const steps = pipelineFor(stage, refusalCode);
  // A completed response is itself the evidence: the outbound scan is
  // fail-closed, so an answer could not exist if it had not passed.
  const scanPassed = stage === "completed";

  return (
    <aside
      className="panel flex h-full min-h-0 flex-col gap-5 overflow-y-auto p-5"
      aria-label="Privacy Inspector"
    >
      <header>
        <h2 className="text-[11px] font-semibold uppercase tracking-wide text-muted">
          Privacy Inspector
        </h2>
        <p
          className="mt-1 flex items-center gap-2 text-base font-semibold"
          aria-live="polite"
          data-testid="inspector-stage"
        >
          {busy ? (
            <span className="h-2 w-2 animate-pulse rounded-full bg-accent" aria-hidden />
          ) : null}
          <span
            className={
              stage === "refused" ? "text-danger" : stage === "completed" ? "text-protect" : "text-ink"
            }
          >
            {STAGE_LABELS[stage]}
          </span>
        </p>
      </header>

      {refusalCode !== null ? (
        <BlockedNotice code={refusalCode} message={refusalMessage ?? ""} />
      ) : null}

      <section aria-labelledby="metrics-heading">
        <h3
          id="metrics-heading"
          className="text-[11px] font-semibold uppercase tracking-wide text-muted"
        >
          Request
        </h3>
        <dl className="mt-2 grid grid-cols-2 gap-2">
          <MetricCard label="Latency" value={formatLatency(elapsedMs)} />
          <MetricCard
            label="Entities"
            value={summary === null ? null : String(summary.detected)}
          />
          <MetricCard label="Provider" value={provider} />
          {/* No v1 response carries the policy version, so this is always a
              dash. Kept visible rather than dropped: the absence is the fact. */}
          <MetricCard
            label="Policy"
            value={props.policyVersion === null ? null : `v${props.policyVersion}`}
          />
        </dl>
      </section>

      <section aria-labelledby="pipeline-heading">
        <h3
          id="pipeline-heading"
          className="text-[11px] font-semibold uppercase tracking-wide text-muted"
        >
          Pipeline
        </h3>
        <Pipeline steps={steps} />
      </section>

      {document !== null ? (
        <section aria-labelledby="doc-section-heading">
          <h3
            id="doc-section-heading"
            className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted"
          >
            Document
          </h3>
          <DocumentCard document={document} />
        </section>
      ) : null}

      {summary !== null ? (
        <>
          <section aria-labelledby="detected-heading">
            <h3
              id="detected-heading"
              className="text-[11px] font-semibold uppercase tracking-wide text-muted"
            >
              Detected ({summary.detected})
            </h3>
            <EntityBadges types={summary.entity_types} />
          </section>

          <ProtectedPayload summary={summary} scanPassed={scanPassed} preview={preview} />
        </>
      ) : null}

      {attestation !== null ? <Attestation digest={attestation} /> : null}

      <section aria-labelledby="diagnostics-heading" className="mt-auto pt-2">
        <h3
          id="diagnostics-heading"
          className="text-[11px] font-semibold uppercase tracking-wide text-muted"
        >
          Diagnostics
        </h3>
        <dl className="mt-2 space-y-1">
          <DiagnosticRow label="Request ID" value={requestId} />
          <DiagnosticRow label="Session" value={sessionId} />
        </dl>
      </section>
    </aside>
  );
}
