"use client";

import { useEffect, useRef } from "react";

import { FLOW_STEPS } from "@/lib/system";

/**
 * A modal describing the end-to-end flow.
 *
 * Built as a native `<dialog>` rather than a div with `role="dialog"`, because
 * the browser then supplies focus trapping, Escape-to-close, inert background,
 * and the top layer for free -- all of which are easy to implement badly by
 * hand. `showModal()` is called from an effect rather than rendering `open`,
 * since the `open` attribute alone produces a non-modal dialog with none of
 * those behaviours.
 *
 * Presentation only: this is the documented architecture, not a trace of any
 * request, and it is labelled that way so nobody reads it as live state.
 */

export function HowItWorks({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-labelledby="how-it-works-heading"
      className="w-[min(28rem,calc(100vw-2rem))] rounded-lg border border-edge bg-panel p-0
                 text-ink backdrop:bg-black/60"
      // Fires for Escape as well as an explicit close, so state stays in sync.
      onClose={onClose}
      onClick={(event) => {
        // Clicking the backdrop closes. The backdrop is the dialog element
        // itself; a click on the content bubbles from a child, so comparing
        // the target distinguishes them.
        if (event.target === ref.current) onClose();
      }}
    >
      <div className="p-5">
        <h2 id="how-it-works-heading" className="text-sm font-semibold">
          How it works
        </h2>
        <p className="mt-1 text-[11px] text-muted">
          The path every request takes through the gateway.
        </p>

        <ol className="mt-4 space-y-0">
          {FLOW_STEPS.map((step, index) => (
            <li key={step}>
              <div className="flex items-center gap-2.5">
                <span className="w-5 shrink-0 text-right font-mono text-[10px] text-muted">
                  {index + 1}
                </span>
                <span className="text-xs text-ink">{step}</span>
              </div>
              {index < FLOW_STEPS.length - 1 ? (
                <div className="ml-[0.6rem] h-2.5 border-l border-edge" aria-hidden />
              ) : null}
            </li>
          ))}
        </ol>

        <button type="button" className="btn mt-5 w-full" onClick={onClose} autoFocus>
          Close
        </button>
      </div>
    </dialog>
  );
}
