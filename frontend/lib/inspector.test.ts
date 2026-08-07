import { describe, expect, it } from "vitest";

import { GATEWAY_STAGES, pipelineFor } from "./inspector";

/**
 * The pipeline reports outcomes it can justify and nothing else.
 *
 * architecture.md 22.6: "The UI must not claim to receive private internal
 * events that the API does not expose." A synchronous v1 response carries no
 * per-stage trace, so every status here has to be derivable from the outcome
 * alone. These tests exist to stop a future change from making the panel
 * cheerfully assert progress it cannot observe.
 */

describe("pipelineFor", () => {
  it("marks every step completed once an answer arrives", () => {
    // Justified: a restored answer cannot exist unless detection, protection,
    // the outbound scan, the provider call, and restoration all happened.
    const steps = pipelineFor("completed", null);

    expect(steps).toHaveLength(GATEWAY_STAGES.length);
    expect(steps.every((step) => step.status === "done")).toBe(true);
  });

  it("leaves every step pending while the request is in flight", () => {
    // The client cannot see which stage is running, so highlighting one would
    // be theatre.
    const steps = pipelineFor("in_flight", null);

    expect(steps.every((step) => step.status === "pending")).toBe(true);
  });

  it("stops at policy and reaches nothing further when the policy blocks", () => {
    const steps = pipelineFor("refused", "POLICY_VIOLATION");
    const byLabel = Object.fromEntries(steps.map((step) => [step.label, step.status]));

    expect(byLabel["Validate"]).toBe("done");
    expect(byLabel["Detect sensitive data"]).toBe("done");
    expect(byLabel["Apply policy"]).toBe("blocked");
    // The point of the block: nothing was transmitted.
    expect(byLabel["Provider call"]).toBe("skipped");
    expect(byLabel["Outbound scan"]).toBe("skipped");
  });

  it("distinguishes a policy block from a failure", () => {
    const blocked = pipelineFor("refused", "POLICY_VIOLATION");
    const failed = pipelineFor("refused", "VAULT_UNAVAILABLE");

    expect(blocked.some((step) => step.status === "blocked")).toBe(true);
    expect(blocked.some((step) => step.status === "failed")).toBe(false);
    expect(failed.some((step) => step.status === "failed")).toBe(true);
  });

  it("fails at validation for an unauthenticated request", () => {
    const steps = pipelineFor("refused", "AUTHENTICATION_REQUIRED");

    expect(steps[0]?.status).toBe("failed");
    expect(steps[1]?.status).toBe("skipped");
  });

  it("claims nothing when the refusal does not locate itself", () => {
    // A transport failure says nothing about how far the request got, so
    // guessing a position would be fabrication.
    for (const code of ["GATEWAY_UNREACHABLE", "NETWORK", "INTERNAL_ERROR"]) {
      const steps = pipelineFor("refused", code);
      expect(steps.every((step) => step.status === "pending")).toBe(true);
    }
  });

  it("lists the documented stages in pipeline order", () => {
    expect(GATEWAY_STAGES[0]).toBe("Validate");
    expect(GATEWAY_STAGES.indexOf("Outbound scan")).toBeLessThan(
      GATEWAY_STAGES.indexOf("Provider call"),
    );
    expect(GATEWAY_STAGES[GATEWAY_STAGES.length - 1]).toBe("Restore authorized values");
  });
});
