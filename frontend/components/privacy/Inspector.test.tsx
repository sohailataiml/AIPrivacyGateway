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
  preview: null,
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

const PREVIEW = {
  text: "Patient ⟦PERSON:••••⟧ was contacted at ⟦EMAIL_ADDRESS:••••⟧.",
  entity_summary: [
    { entity_type: "PERSON", count: 1, action: "tokenize" },
    { entity_type: "EMAIL_ADDRESS", count: 1, action: "tokenize" },
  ],
  outbound_scan: "passed",
  truncated: false,
};

describe("protected payload preview", () => {
  it("shows the masked text the provider actually received", () => {
    renderInspector({ preview: PREVIEW });

    expect(screen.getByTestId("preview-text").textContent).toContain("⟦PERSON:••••⟧");
    expect(screen.getByTestId("preview-text").textContent).toContain("Patient");
  });

  it("renders no full token, because the server sent none", () => {
    // The masking is one-way and happens before this component sees anything.
    // A client asked to mask would still hold the token in memory and in the
    // network tab, which is why the server does it instead.
    renderInspector({ preview: PREVIEW });

    const rendered = screen.getByTestId("protected-payload").textContent ?? "";
    expect(rendered).not.toContain("SGW:");
    expect(rendered).not.toMatch(/[0-9A-HJKMNP-TV-Z]{26}/);
  });

  it("lists each entity type with its count and the action applied", () => {
    renderInspector({ preview: PREVIEW });
    const entities = screen.getByTestId("preview-entities");

    expect(entities.textContent).toContain("PERSON");
    expect(entities.textContent).toContain("EMAIL_ADDRESS");
    // Lowercase in the DOM; the panel uppercases it with CSS. Asserting the
    // rendered text rather than the styled appearance keeps this from breaking
    // on a style change that alters nothing about the data.
    expect(entities.textContent).toContain("tokenized");
  });

  it("counts the values transformed", () => {
    renderInspector({ preview: PREVIEW });

    // 12 tokenized + 2 redacted + 1 pseudonymized from the shared summary.
    expect(screen.getByTestId("protected-payload").textContent).toContain(
      "15 sensitive values transformed",
    );
  });

  it("says when the preview was shortened", () => {
    renderInspector({ preview: { ...PREVIEW, truncated: true } });

    expect(screen.getByText("Shortened for display.")).toBeTruthy();
  });

  it("falls back to counts when the deployment has not enabled the preview", () => {
    // The default. The section still reports what happened; it just cannot
    // show the payload, and says so rather than rendering an empty box.
    renderInspector({ preview: null });

    expect(screen.queryByTestId("preview-text")).toBeNull();
    expect(screen.queryByTestId("preview-entities")).toBeNull();
    expect(screen.getByTestId("protected-payload").textContent).toContain(
      "never stored or returned",
    );
  });

  it("shows no preview block when the server sent a summary but no text", () => {
    // The document path: entity counts without body text.
    renderInspector({ preview: { ...PREVIEW, text: null } });

    expect(screen.queryByTestId("preview-text")).toBeNull();
    expect(screen.getByTestId("preview-entities")).toBeTruthy();
  });
});

describe("protected payload", () => {
  it("counts protected spans without showing any payload", () => {
    renderInspector();
    const payload = screen.getByTestId("protected-payload");

    // tokenized 12 + redacted 2 + pseudonymized 1; `allowed` is excluded
    // because an allowed value was sent as written.
    expect(payload.textContent).toContain("15 sensitive values transformed");
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
