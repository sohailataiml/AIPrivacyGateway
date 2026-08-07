"use client";

import { STATUS_GLYPH, STATUS_TEXT, type PipelineStep } from "@/lib/inspector";

/**
 * The gateway pipeline as a vertical list of steps with known outcomes.
 *
 * Status is carried three ways at once -- glyph, colour, and the word itself --
 * because any one of them alone excludes someone. The text is not
 * `sr-only`: a colour-blind sighted user gets nothing from a green tick and a
 * red cross that differ only in hue, so "Completed" and "Blocked" are on
 * screen for everyone.
 *
 * The connector between steps is `aria-hidden`. It is a downward arrow that
 * means "then", which the list order already conveys; announcing it eight times
 * would be noise.
 */

const STATUS_TONE: Record<PipelineStep["status"], string> = {
  pending: "text-muted",
  done: "text-protect",
  blocked: "text-warn",
  failed: "text-danger",
  skipped: "text-muted/60",
};

export function Pipeline({ steps }: { steps: readonly PipelineStep[] }) {
  return (
    <ol className="mt-3 space-y-0" data-testid="pipeline">
      {steps.map((step, index) => (
        <li key={step.label}>
          <div className="flex items-start gap-2.5">
            <span
              className={`mt-px w-3 shrink-0 text-center font-mono text-xs leading-5 ${STATUS_TONE[step.status]}`}
              aria-hidden
            >
              {STATUS_GLYPH[step.status]}
            </span>
            <span className="min-w-0 flex-1 text-xs leading-5 text-ink">{step.label}</span>
            <span
              className={`shrink-0 text-[10px] uppercase tracking-wide leading-5 ${STATUS_TONE[step.status]}`}
            >
              {STATUS_TEXT[step.status]}
            </span>
          </div>
          {index < steps.length - 1 ? (
            <div className="ml-[0.3rem] h-2 border-l border-edge" aria-hidden />
          ) : null}
        </li>
      ))}
    </ol>
  );
}
