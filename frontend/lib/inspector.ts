/**
 * The Privacy Inspector's state machine.
 *
 * architecture.md section 22.6 is explicit about what these are: "UI progress
 * states based on request lifecycle and returned metadata. The UI must not
 * claim to receive private internal events that the API does not expose."
 *
 * Version 1 of the API is synchronous and emits no per-stage events, so the
 * inspector never *animates* through stages. What it may do -- and now does --
 * is report each stage's outcome once the outcome is known, because a restored
 * answer is proof the whole pipeline ran and a refusal names where it stopped.
 * That is inference from returned data, not theatre. Highlighting "Tokenizing"
 * because 300ms elapsed would be theatre, and theatre in a privacy inspector is
 * a lie about the one thing the product asks to be trusted on.
 */

export type InspectorStage = "idle" | "uploading" | "in_flight" | "completed" | "refused";

export const STAGE_LABELS: Record<InspectorStage, string> = {
  idle: "Idle",
  uploading: "Uploading document",
  in_flight: "Gateway processing",
  completed: "Completed",
  refused: "Refused",
};

/** What a single pipeline step is currently known to have done. */
export type StepStatus = "pending" | "done" | "blocked" | "failed" | "skipped";

export interface PipelineStep {
  readonly label: string;
  readonly status: StepStatus;
}

/**
 * The stages the gateway performs, in order.
 *
 * These mirror the server pipeline (protect -> serialize -> scan -> transmit ->
 * restore). They are a description of the system, not a live trace.
 */
export const GATEWAY_STAGES: readonly string[] = [
  "Validate",
  "Detect sensitive data",
  "Apply policy",
  "Protect values",
  "Secure mappings",
  "Outbound scan",
  "Provider call",
  "Restore authorized values",
];

/**
 * Where a given refusal stopped the pipeline.
 *
 * Only codes whose position is genuinely determined by the gateway's own
 * ordering appear here. `POLICY_VIOLATION` is raised while applying policy, so
 * detection had already succeeded and nothing was transmitted. Authentication
 * and request-shape failures happen before any of it.
 *
 * Anything absent from this map is left `unknown` on purpose: a transport
 * failure or an unavailable dependency tells the client nothing about how far
 * the request got, and guessing would be exactly the fabrication section 22.6
 * forbids.
 */
const STOPPED_AT: Readonly<Record<string, number>> = {
  AUTHENTICATION_REQUIRED: 0,
  AUTHENTICATION_FAILED: 0,
  AUTHORIZATION_FAILED: 0,
  INVALID_REQUEST: 0,
  RATE_LIMIT_EXCEEDED: 0,
  POLICY_VIOLATION: 2,
  PRIVACY_DETECTOR_UNAVAILABLE: 1,
  VAULT_UNAVAILABLE: 4,
  VAULT_ENCRYPTION_FAILED: 4,
  RESTORATION_FAILED: 7,
};

/** Refusals that are the policy doing its job rather than something breaking. */
export const BLOCKING_CODES: ReadonlySet<string> = new Set(["POLICY_VIOLATION"]);

/**
 * Derive each step's status from what the client actually observed.
 *
 * A completed request proves every step ran: the answer contains restored
 * values, which cannot exist unless detection, protection, the outbound scan,
 * the provider call, and restoration all happened in order.
 */
export function pipelineFor(stage: InspectorStage, refusalCode: string | null): PipelineStep[] {
  if (stage === "completed") {
    return GATEWAY_STAGES.map((label) => ({ label, status: "done" as const }));
  }

  if (stage !== "refused") {
    return GATEWAY_STAGES.map((label) => ({ label, status: "pending" as const }));
  }

  const stoppedAt = refusalCode === null ? undefined : STOPPED_AT[refusalCode];
  if (stoppedAt === undefined) {
    // Position unknown. Reporting every step as pending is the honest answer.
    return GATEWAY_STAGES.map((label) => ({ label, status: "pending" as const }));
  }

  const failureStatus: StepStatus =
    refusalCode !== null && BLOCKING_CODES.has(refusalCode) ? "blocked" : "failed";

  return GATEWAY_STAGES.map((label, index) => {
    if (index < stoppedAt) return { label, status: "done" as const };
    if (index === stoppedAt) return { label, status: failureStatus };
    return { label, status: "skipped" as const };
  });
}

/**
 * Text shown beside each status, so the state never depends on colour alone.
 * Read by screen readers and visible to sighted users for the same reason.
 */
export const STATUS_TEXT: Record<StepStatus, string> = {
  pending: "Not started",
  done: "Completed",
  blocked: "Blocked",
  failed: "Failed",
  skipped: "Not reached",
};

/** A glyph per status. Paired with STATUS_TEXT; never the only signal. */
export const STATUS_GLYPH: Record<StepStatus, string> = {
  pending: "○",
  done: "✓",
  blocked: "⦸",
  failed: "✕",
  skipped: "–",
};
