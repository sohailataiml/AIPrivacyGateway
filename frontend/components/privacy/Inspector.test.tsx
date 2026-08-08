import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { PrivacySummary } from "@/lib/gateway";

import { Inspector, type InspectorProps } from "./Inspector";

/**
 * What the inspector shows, and -- more importantly -- what it must never show.
 *
 * The negative assertions are the reason this file exists. `PrivacySummary`
 * carries counts and type names only, so there is no prop through which an
 * original value could arrive; these tests guard the next layer of that, which
 * is a future change adding one.
 */

const SUMMARY: PrivacySummary = {
  detected: 16,
  tokenized: 12,
  redacted: 2,
  pseudonymized: 1,
  blocked: 0,
  allowed: 1,
  restored: 12,
  unknown_tokens: 0,
  entity_types: { PERSON: 4, EMAIL_ADDRESS: 2, PHONE_NUMBER: 5, LOCATION: 4, DATE_TIME: 1 },
};

const BASE: InspectorProps = {
  stage: "completed",
  summary: SUMMARY,
  requestId: "970003e9-1721-40a7-b291-7332540bb795",
  sessionId: "2ad6f1cf-c68d-4800-90a1-11921b1ebcdf",
  policyVersion: null,
  attestation: "61d269aa4f1c8b3e77d2905ac1ff0e5b6a8c4413ee9d2277cc31b0a5f4e6d8b2",
  elapsedMs: 2900,
  refusalCode: null,
  refusalMessage: null,
  provider: "mock",
  document: null,
};

function renderInspector(overrides: Partial<InspectorProps> = {}) {
  return render(<Inspector {...BASE} {...overrides} />);
}

describe("metric cards", () => {
  it("shows latency, entity count, and provider from the response", () => {
    renderInspector();

    expect(screen.getByText("2.9 s")).toBeTruthy();
    expect(screen.getByText("16")).toBeTruthy();
    expect(screen.getByText("mock")).toBeTruthy();
  });

  it("renders an em dash for policy version, which no v1 response carries", () => {
    // Not a placeholder to fill in later: the absence is the honest report.
    renderInspector();

    const policy = screen.getByText("Policy").closest("div");
    expect(within(policy as HTMLElement).getByText("—")).toBeTruthy();
  });

  it("renders milliseconds below a second rather than rounding to 0.0 s", () => {
    renderInspector({ elapsedMs: 420 });

    expect(screen.getByText("420 ms")).toBeTruthy();
  });
});

describe("entity badges", () => {
  it("shows the backend entity names verbatim with counts", () => {
    renderInspector();
    const badges = screen.getByTestId("entity-badges");

    for (const [type, count] of Object.entries(SUMMARY.entity_types)) {
      const badge = within(badges).getByText(type);
      expect(badge).toBeTruthy();
      expect(badge.closest("li")?.textContent).toContain(String(count));
    }
  });

  it("does not prettify the names into a second vocabulary", () => {
    renderInspector();

    expect(screen.queryByText("Email address")).toBeNull();
    expect(within(screen.getByTestId("entity-badges")).getByText("EMAIL_ADDRESS")).toBeTruthy();
  });

  it("says so plainly when nothing was found", () => {
    renderInspector({ summary: { ...SUMMARY, detected: 0, entity_types: {} } });

    expect(screen.getByText("Nothing sensitive was found.")).toBeTruthy();
  });
});

describe("pipeline", () => {
  it("marks steps completed with text, not colour alone", () => {
    renderInspector();
    const pipeline = screen.getByTestId("pipeline");

    expect(within(pipeline).getByText("Validate")).toBeTruthy();
    expect(within(pipeline).getAllByText("Completed").length).toBe(8);
  });

  it("shows a blocked step and unreached steps when policy refuses", () => {
    renderInspector({
      stage: "refused",
      summary: null,
      attestation: null,
      refusalCode: "POLICY_VIOLATION",
      refusalMessage: "The request was blocked by the active privacy policy.",
    });
    const pipeline = screen.getByTestId("pipeline");

    expect(within(pipeline).getByText("Blocked")).toBeTruthy();
    expect(within(pipeline).getAllByText("Not reached").length).toBeGreaterThan(0);
  });
});

describe("blocked requests", () => {
  it("presents a policy block as the control working", () => {
    renderInspector({
      stage: "refused",
      summary: null,
      attestation: null,
      refusalCode: "POLICY_VIOLATION",
      refusalMessage: "The request was blocked by the active privacy policy.",
    });
    const notice = screen.getByTestId("blocked-notice");

    expect(notice.textContent).toContain("Request blocked by privacy policy");
    expect(notice.textContent).toContain("A high-risk sensitive entity was detected.");
    expect(notice.textContent).toContain("The request was not sent to the provider.");
  });

  it("invents no entity type for a block, because none is returned", () => {
    renderInspector({
      stage: "refused",
      summary: null,
      attestation: null,
      refusalCode: "POLICY_VIOLATION",
      refusalMessage: "The request was blocked by the active privacy policy.",
    });

    expect(screen.queryByText(/US_SSN/)).toBeNull();
    expect(screen.queryByText(/Entity type/i)).toBeNull();
  });

  it("uses the gateway's own message for a non-policy refusal", () => {
    renderInspector({
      stage: "refused",
      summary: null,
      attestation: null,
      refusalCode: "VAULT_UNAVAILABLE",
      refusalMessage: "The secure mapping service is unavailable.",
    });
    const notice = screen.getByTestId("blocked-notice");

    expect(notice.textContent).toContain("The secure mapping service is unavailable.");
    expect(notice.textContent).not.toContain("blocked by privacy policy");
  });
});

describe("outbound attestation", () => {
  it("shows a shortened digest and claims attested, not verified", () => {
    // The browser has no audit key, so it cannot verify this digest and must
    // not imply that it did.
    renderInspector();

    expect(screen.getByText("ATTESTED")).toBeTruthy();
    expect(screen.queryByText("VERIFIED")).toBeNull();
    expect(screen.getByTestId("attestation-digest").textContent).toBe("61d269aa4f1c…");
  });

  it("explains what the digest is", () => {
    renderInspector();

    expect(screen.getByText(/Keyed digest of the protected outbound request/)).toBeTruthy();
  });

  it("shows no attestation section when the response carried none", () => {
    renderInspector({ attestation: null });

    expect(screen.queryByTestId("attestation-digest")).toBeNull();
  });
});

describe("outbound totals", () => {
  it("counts protected spans without showing any payload", () => {
    renderInspector();
    const payload = screen.getByTestId("protected-payload");

    // tokenized 12 + redacted 2 + pseudonymized 1; `allowed` is excluded
    // because an allowed value was sent as written.
    expect(payload.textContent).toContain("15");
  });

  it("does not repeat the payload card the conversation already shows", () => {
    // The panel keeps totals; `SecurityTrace` owns the masked text. Two copies
    // of the same card was the whole reason the page needed scrolling.
    renderInspector();

    expect(screen.queryByTestId("preview-text")).toBeNull();
    expect(screen.queryByTestId("preview-entities")).toBeNull();
    expect(screen.queryByText(/What the LLM received/i)).toBeNull();
  });

  it("reports the outbound scan only once an answer proves it passed", () => {
    renderInspector();
    expect(screen.getByTestId("outbound-scan").textContent).toBe("PASSED");

    renderInspector({ stage: "in_flight" });
    expect(screen.getAllByTestId("outbound-scan")[1]?.textContent).toBe("—");
  });
});

describe("diagnostics", () => {
  it("keeps request and session ids available in full", () => {
    renderInspector();

    expect(screen.getByText(BASE.requestId as string)).toBeTruthy();
    expect(screen.getByText(BASE.sessionId as string)).toBeTruthy();
  });

  it("wraps long identifiers instead of forcing a horizontal scroll", () => {
    renderInspector();
    const requestId = screen.getByText(BASE.requestId as string);

    expect(requestId.className).toContain("break-all");
  });
});

describe("accessibility", () => {
  it("labels the panel and gives each section a heading", () => {
    renderInspector();

    expect(screen.getByLabelText("Privacy Inspector")).toBeTruthy();
    expect(screen.getByRole("heading", { name: /Pipeline/ })).toBeTruthy();
    expect(screen.getByRole("heading", { name: /Request/ })).toBeTruthy();
    expect(screen.getByRole("heading", { name: /Diagnostics/ })).toBeTruthy();
  });

  it("announces stage changes politely", () => {
    renderInspector();

    expect(screen.getByTestId("inspector-stage").getAttribute("aria-live")).toBe("polite");
  });
});
