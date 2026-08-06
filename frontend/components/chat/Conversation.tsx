"use client";

/**
 * The conversation panel.
 *
 * Model output is rendered as **plain text**, not markdown and not HTML.
 * architecture.md section 22.15 asks for "XSS-safe rendering of model output"
 * and "markdown rendering disabled initially". React escapes by default, so the
 * safe thing here is simply not to reach for `dangerouslySetInnerHTML` — and
 * the reason it is worth stating is that a restored assistant message is the
 * one string on this page whose content an upstream model chose.
 */

export type Author = "you" | "gateway" | "system";

export interface Turn {
  id: string;
  author: Author;
  text: string;
  /** Set on a turn that came from a document rather than typed. */
  documentName?: string;
}

const AUTHOR_STYLES: Record<Author, string> = {
  you: "border-edge bg-surface",
  gateway: "border-accent/40 bg-accent/5",
  system: "border-warn/40 bg-warn/5",
};

const AUTHOR_LABELS: Record<Author, string> = {
  you: "You",
  gateway: "Gateway",
  system: "Notice",
};

export function Conversation({ turns }: { turns: readonly Turn[] }) {
  if (turns.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center p-8 text-center">
        <div className="max-w-md space-y-2">
          <p className="text-sm text-muted">
            Send a prompt, or attach a document and ask a question about it.
          </p>
          <p className="text-xs text-muted">
            Sensitive values are replaced with session tokens before anything leaves the
            gateway, and restored in the answer you see.
          </p>
        </div>
      </div>
    );
  }

  return (
    <ol className="flex flex-1 flex-col gap-3 overflow-y-auto p-4" aria-label="Conversation">
      {turns.map((turn) => (
        <li
          key={turn.id}
          className={`rounded-lg border px-4 py-3 ${AUTHOR_STYLES[turn.author]}`}
        >
          <p className="mb-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
            {AUTHOR_LABELS[turn.author]}
            {turn.documentName ? (
              <span className="rounded border border-edge px-1.5 py-0.5 font-mono text-[10px] normal-case text-muted">
                {turn.documentName}
              </span>
            ) : null}
          </p>
          {/* Plain text. No markdown, no HTML injection surface. */}
          <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{turn.text}</p>
        </li>
      ))}
    </ol>
  );
}
