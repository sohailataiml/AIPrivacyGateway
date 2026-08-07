"use client";

import { ENCRYPTION_DESCRIPTION, STORAGE_DESCRIPTION } from "@/lib/system";

/**
 * The status of the document this turn was about.
 *
 * What is shown is bounded by what the API returns for a document: an id, the
 * filename the caller sent, a content type, a byte size, and a status. The id
 * is deliberately absent from the display -- it is an opaque handle with no
 * meaning to a reader, and it is the one field here that identifies a stored
 * object.
 *
 * Nothing about *where* it went is available to this client, and that is by
 * design: no bucket, no object key, no tenant path, no encrypted filename. The
 * storage and encryption lines below are constants describing the deployment
 * (see `lib/system.ts`), rendered under a "System" heading so they are not
 * mistaken for per-document telemetry.
 */

export interface DocumentStatus {
  /** The filename the user chose. Never the encrypted stored name. */
  name: string;
  /** Backend `status`, e.g. "stored". Null until the upload returns. */
  status: string | null;
  byteSize: number | null;
  /** Entities found in this document, once it has been processed. */
  detected: number | null;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function Check({ label, done }: { label: string; done: boolean }) {
  return (
    <li className={`flex items-center gap-1.5 ${done ? "text-protect" : "text-muted"}`}>
      <span aria-hidden>{done ? "✓" : "○"}</span>
      <span className="text-[11px]">{label}</span>
      <span className="sr-only">{done ? "completed" : "not started"}</span>
    </li>
  );
}

export function DocumentCard({ document }: { document: DocumentStatus }) {
  // "stored" is the API's own terminal status. Anything else means the upload
  // returned but has not reached that state, so the checks stay open rather
  // than being asserted optimistically.
  const stored = document.status === "stored";

  return (
    <section
      className="rounded-md border border-edge bg-surface p-3"
      aria-labelledby="document-heading"
      data-testid="document-card"
    >
      <h3
        id="document-heading"
        className="truncate font-mono text-xs text-ink"
        title={document.name}
      >
        {document.name}
      </h3>

      <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
        <Check label="Uploaded" done={document.status !== null} />
        <Check label="Encrypted" done={stored} />
        <Check label="Stored" done={stored} />
      </ul>

      <dl className="mt-2.5 space-y-0.5 border-t border-edge pt-2 text-[11px]">
        {document.byteSize !== null ? (
          <div className="flex justify-between gap-3">
            <dt className="text-muted">Size</dt>
            <dd className="font-mono text-ink">{formatBytes(document.byteSize)}</dd>
          </div>
        ) : null}
        {document.detected !== null ? (
          <div className="flex justify-between gap-3">
            <dt className="text-muted">Detected</dt>
            <dd className="font-mono text-ink">
              {document.detected} {document.detected === 1 ? "entity" : "entities"}
            </dd>
          </div>
        ) : null}
        <div className="flex justify-between gap-3">
          <dt className="text-muted">Storage</dt>
          <dd className="text-right text-ink">{STORAGE_DESCRIPTION}</dd>
        </div>
        <div className="flex justify-between gap-3">
          <dt className="text-muted">Encryption</dt>
          <dd className="text-right text-ink">{ENCRYPTION_DESCRIPTION}</dd>
        </div>
      </dl>
    </section>
  );
}
