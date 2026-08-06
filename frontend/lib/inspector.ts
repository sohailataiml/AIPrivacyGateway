/**
 * The Privacy Inspector's state machine.
 *
 * architecture.md section 22.6 is explicit about what these are: "UI progress
 * states based on request lifecycle and returned metadata. The UI must not
 * claim to receive private internal events that the API does not expose."
 *
 * Version 1 of the API is synchronous and emits no per-stage events, so the
 * inspector advances on what the client itself knows -- the request left, the
 * response arrived -- and then reports the *returned* metadata. It never
 * animates through stages it did not observe. Showing "Tokenizing" because
 * 300ms elapsed would be theatre, and theatre in a privacy inspector is a lie
 * about the one thing the product asks to be trusted on.
 */

export type InspectorStage =
  | "idle"
  | "uploading"
  | "in_flight"
  | "completed"
  | "refused";

export const STAGE_LABELS: Record<InspectorStage, string> = {
  idle: "Idle",
  uploading: "Uploading document",
  in_flight: "Gateway processing",
  completed: "Completed",
  refused: "Refused",
};

/**
 * The stages the gateway performs inside `in_flight`.
 *
 * Listed for the operator's understanding of what the request is doing, and
 * deliberately *not* individually highlighted: the client cannot see which one
 * is running. They are documentation on screen, not progress.
 */
export const GATEWAY_STAGES: readonly string[] = [
  "Validate",
  "Detect sensitive data",
  "Apply policy",
  "Tokenize",
  "Secure mappings",
  "Scan outbound payload",
  "Call provider",
  "Restore authorized values",
];
