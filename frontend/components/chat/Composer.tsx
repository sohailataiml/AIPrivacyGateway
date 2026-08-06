"use client";

import { useRef, useState } from "react";

const ACCEPTED = ".txt,.pdf,.docx";
const ACCEPTED_LABEL = "TXT, PDF, or DOCX";

/**
 * The prompt composer, with document attachment.
 *
 * One control for both paths on purpose. To the person using it, "ask about
 * this" and "ask about this file" are the same intent, and the gateway happens
 * to route them to `/v1/chat` or `/v1/documents/{id}/process`. Splitting them
 * into two forms would make the document path feel like a different product
 * when it is the same guarantee applied to a larger input.
 *
 * When a file is attached the text becomes the *instruction*, and the API
 * requires one -- so the send button stays disabled until there is text either
 * way. That is a real backend constraint surfaced honestly rather than a
 * placeholder instruction invented on the caller's behalf.
 */

export interface ComposerProps {
  disabled: boolean;
  attachment: File | null;
  onAttach: (file: File | null) => void;
  onSend: (text: string) => void;
}

export function Composer({ disabled, attachment, onAttach, onSend }: ComposerProps) {
  const [text, setText] = useState("");
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const canSend = !disabled && text.trim().length > 0;

  function submit() {
    if (!canSend) return;
    onSend(text.trim());
    setText("");
  }

  function takeFirst(files: FileList | null) {
    const file = files?.[0];
    if (file) onAttach(file);
  }

  return (
    <form
      className={`panel m-4 mt-0 p-3 transition ${dragging ? "border-accent" : ""}`}
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        takeFirst(event.dataTransfer.files);
      }}
    >
      {attachment ? (
        <div className="mb-2 flex items-center justify-between rounded border border-edge bg-surface px-3 py-2">
          <span className="truncate font-mono text-xs text-ink">{attachment.name}</span>
          <button
            type="button"
            className="btn-quiet ml-3 shrink-0"
            onClick={() => {
              onAttach(null);
              if (fileInput.current) fileInput.current.value = "";
            }}
          >
            Remove
          </button>
        </div>
      ) : null}

      <label htmlFor="composer" className="sr-only">
        {attachment ? "What to do with the document" : "Prompt"}
      </label>
      <textarea
        id="composer"
        className="field min-h-[76px] resize-y"
        placeholder={
          attachment
            ? "What should the model do with this document?"
            : `Type a prompt, or drop a file (${ACCEPTED_LABEL})…`
        }
        value={text}
        disabled={disabled}
        onChange={(event) => setText(event.target.value)}
        onKeyDown={(event) => {
          // Enter sends; Shift+Enter is a newline. Standard for a composer, and
          // the multi-line case is common enough here to be worth supporting.
          if (event.key === "Enter" && !event.shiftKey) {
            event.preventDefault();
            submit();
          }
        }}
      />

      <div className="mt-2 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <input
            ref={fileInput}
            type="file"
            accept={ACCEPTED}
            className="sr-only"
            id="attachment"
            onChange={(event) => takeFirst(event.target.files)}
          />
          <label htmlFor="attachment" className="btn-quiet cursor-pointer">
            Attach document
          </label>
          <span className="text-[11px] text-muted">{ACCEPTED_LABEL}</span>
        </div>
        <button type="submit" className="btn" disabled={!canSend}>
          {attachment ? "Send document" : "Send"}
        </button>
      </div>
    </form>
  );
}
