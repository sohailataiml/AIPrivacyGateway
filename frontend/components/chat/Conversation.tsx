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
 *
 * The gateway turn is labelled "LLM Response (Restored)" because that is the
 * single most important fact about it: the tokens that went to the provider
 * have been swapped back for the real values, so what is on screen is not what
 * the provider saw. Which model produced it is secondary, and a mock provider
 * is a deployment detail rather than a property of the answer — so it sits in a
 * small badge instead of leading the text, where "Mock provider reply" used to
 * read as if the *gateway* were fake.
 */

export type Author = "you" | "gateway" | "system";

export interface Turn {
  id: string;
  author: Author;
  text: string;
  /** Set on a turn that came from a document rather than typed. */
  documentName?: string;
  /** The provider that answered, for a gateway turn. */
  provider?: string;
  /** Restored value count, when the response reported one. */
  restored?: number;
}

const AUTHOR_STYLES: Record<Author, string> = {
  you: "border-edge bg-surface",
  gateway: "border-accent/40 bg-accent/5",
  system: "border-warn/40 bg-warn/5",
};

const AUTHOR_LABELS: Record<Author, string> = {
  you: "You",
  gateway: "LLM Response (Restored)",
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
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <p
              className={`text-[11px] font-semibold uppercase tracking-wide ${
                turn.author === "gateway" ? "text-accent" : "text-muted"
              }`}
            >
              {AUTHOR_LABELS[turn.author]}
            </p>
            {turn.provider ? (
              <span className="rounded border border-edge px-1.5 py-0.5 font-mono text-[10px] text-muted">
                {turn.provider === "mock" ? "Mock provider" : turn.provider}
              </span>
            ) : null}
            {turn.restored !== undefined && turn.restored > 0 ? (
              <span className="rounded border border-protect/40 bg-protect/10 px-1.5 py-0.5 text-[10px] text-protect">
                {turn.restored} restored
              </span>
            ) : null}
            {turn.documentName ? (
              <span className="max-w-[14rem] truncate rounded border border-edge px-1.5 py-0.5 font-mono text-[10px] text-muted">
                {turn.documentName}
              </span>
            ) : null}
          </div>
          {/* Plain text. No markdown, no HTML injection surface. */}
          <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{turn.text}</p>
        </li>
      ))}
    </ol>
  );
}
