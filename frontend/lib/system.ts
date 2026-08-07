/**
 * Static descriptions of how the deployment is built.
 *
 * Everything here is a *constant*, not backend telemetry, and it is isolated in
 * one file precisely so that distinction stays visible. The API returns a
 * document's status; it does not return where the bytes went or how they were
 * sealed, because a caller has no business being told either. So these strings
 * describe the system for a reader, and the components that render them keep
 * them visually separate from live values.
 *
 * The consequence of getting this wrong is a UI that states something untrue
 * with total confidence. If this deployment is ever pointed at a different
 * object store (`OBJECT_STORE_PROVIDER=compatible`, per ADR-0034), the storage
 * line below becomes a lie until someone edits it. That is the cost of stating
 * it at all, accepted here because an interviewer needs to know where documents
 * land, and paid down by keeping it to one line in one file.
 */

/** Where stored documents live. See ADR-0035. */
export const STORAGE_DESCRIPTION = "AWS S3 (private)";

/** How they are sealed before they get there. See ADR-0020, ADR-0021. */
export const ENCRYPTION_DESCRIPTION = "Application-layer, per document";

/**
 * The end-to-end flow, for the "How it works" panel.
 *
 * Presentation only. It is the documented architecture, not a trace of any
 * particular request.
 */
export const FLOW_STEPS: readonly string[] = [
  "Upload",
  "Encrypt",
  STORAGE_DESCRIPTION.replace(" (private)", ""),
  "Extract",
  "Detect",
  "Protect",
  "Outbound scan",
  "LLM",
  "Restore",
  "User",
];
