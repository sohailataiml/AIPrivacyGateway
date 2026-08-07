"use client";

import { useEffect, useRef } from "react";

import type { PolicyValidationResult, RiskyChange } from "@/lib/policies";

/**
 * The confirmation shown before a draft becomes the active policy.
 *
 * Publishing changes what every subsequent request is protected by, so it is
 * the one action in this application that asks twice. The dialog states what
 * will change, warns about anything that weakens a control, and requires an
 * explicit click -- it never publishes on mount or on Enter.
 *
 * Risky changes are warnings, not blocks. An operator may have a good reason to
 * allow an entity type, and refusing would make the product wrong for them; the
 * backend decides what is publishable, and this says plainly what is about to
 * happen.
 */

export interface PublishDialogProps {
  open: boolean;
  version: number;
  summary: readonly string[];
  risky: readonly RiskyChange[];
  validation: PolicyValidationResult | null;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function PublishDialog({
  open,
  version,
  summary,
  risky,
  validation,
  busy,
  onConfirm,
  onCancel,
}: PublishDialogProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  const blocked = validation !== null && !validation.valid;

  return (
    <dialog
      ref={ref}
      aria-labelledby="publish-heading"
      className="w-[min(30rem,calc(100vw-2rem))] rounded-lg border border-edge bg-panel p-0 text-ink backdrop:bg-black/60"
      onClose={onCancel}
      data-testid="publish-dialog"
    >
      <div className="p-5">
        <h2 id="publish-heading" className="text-sm font-semibold">
          Publish policy version {version}?
        </h2>

        {summary.length === 0 ? (
          <p className="mt-2 text-xs text-muted">
            No rule changes. Publishing still creates version {version}.
          </p>
        ) : (
          <ul className="mt-3 space-y-1 text-xs text-ink" data-testid="publish-summary">
            {summary.map((line) => (
              <li key={line} className="flex gap-2">
                <span aria-hidden className="text-muted">
                  ·
                </span>
                {line}
              </li>
            ))}
          </ul>
        )}

        {risky.length > 0 ? (
          <section
            className="mt-4 rounded-md border border-warn/50 bg-warn/10 p-3"
            data-testid="risky-changes"
          >
            <h3 className="flex items-center gap-1.5 text-xs font-semibold text-warn">
              <span aria-hidden>⚠</span> Weakens protection
            </h3>
            <ul className="mt-1.5 space-y-1 text-[11px] text-ink">
              {risky.map((change) => (
                <li key={`${change.entityType}-${change.reason}`}>
                  <span className="font-mono">{change.entityType}</span> — {change.reason}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        {blocked ? (
          <section
            className="mt-4 rounded-md border border-danger/50 bg-danger/10 p-3"
            data-testid="publish-blocked"
          >
            <h3 className="text-xs font-semibold text-danger">Cannot publish</h3>
            <ul className="mt-1.5 space-y-1 text-[11px] text-ink">
              {validation?.problems.map((problem) => (
                <li key={`${problem.field}-${problem.code}`}>
                  <span className="font-mono">{problem.field}</span> — {problem.message}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <div className="mt-5 flex justify-end gap-2">
          <button type="button" className="btn-quiet" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className="btn"
            onClick={onConfirm}
            disabled={busy || blocked}
            data-testid="confirm-publish"
          >
            {busy ? "Publishing…" : `Publish version ${version}`}
          </button>
        </div>
      </div>
    </dialog>
  );
}
