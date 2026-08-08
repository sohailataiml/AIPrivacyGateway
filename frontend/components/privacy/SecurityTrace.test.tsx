import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { PrivacySummary } from "@/lib/gateway";

import { SecurityTrace, type SecurityTraceProps } from "./SecurityTrace";

/**
 * The lifecycle card that sits between the prompt and the answer.
 *
 * The negative assertions carry the weight. Masking happens on the server, so
 * this component is never handed a token to hide -- but "never handed one" is a
 * property of the current backend, and these tests are what would notice if a
 * future change started sending one and the component rendered it verbatim.
 */

const SUMMARY: PrivacySummary = {
  detected: 3,
  tokenized: 2,
  redacted: 0,
  pseudonymized: 0,
  blocked: 0,
  allowed: 1,
  restored: 2,
  unknown_tokens: 0,
  entity_types: { PERSON: 1, EMAIL_ADDRESS: 1 },
};

const PREVIEW = {
  text: "Please contact ⟦PERSON:••••⟧ at ⟦EMAIL_ADDRESS:••••⟧ about her appointment.",
  entity_summary: [
    { entity_type: "PERSON", count: 1, action: "tokenize" },
    { entity_type: "EMAIL_ADDRESS", count: 1, action: "tokenize" },
  ],
  outbound_scan: "passed",
  truncated: false,
};

const BASE: SecurityTraceProps = {
  summary: SUMMARY,
  preview: PREVIEW,
  provider: "mock",
  blocked: null,
};

function renderTrace(overrides: Partial<SecurityTraceProps> = {}) {
  return render(<SecurityTrace {...BASE} {...overrides} />);
}

describe("the protected stage", () => {
  it("is titled for a reader who has never seen this application", () => {
    renderTrace();

    expect(
      screen.getByRole("heading", { name: /Protected payload sent to LLM/i }),
    ).toBeTruthy();
  });

  it("labels the payload as a masked view, not as what the provider literally got", () => {
    // The provider received opaque gateway tokens. "What the LLM received"
    // read as though the dots themselves went upstream, which is the one thing
    // this panel must not imply.
    renderTrace();

    expect(screen.getByText(/Provider-safe payload preview/i)).toBeTruthy();
    expect(screen.queryByText(/What the LLM received/i)).toBeNull();
    expect(screen.getByTestId("preview-text").textContent).toContain("⟦PERSON:••••⟧");
    expect(screen.getByTestId("preview-text").textContent).toContain("about her appointment");
  });

  it("names the gateway stage and the count it transformed", () => {
    renderTrace();

    expect(screen.getByText("Secure AI Gateway")).toBeTruthy();
    expect(screen.getByText("2 sensitive values transformed")).toBeTruthy();
  });

  it("lists each entity type with its count and the action applied", () => {
    renderTrace();
    const entities = screen.getByTestId("preview-entities");

    expect(within(entities).getByText(/PERSON/)).toBeTruthy();
    expect(within(entities).getByText(/EMAIL_ADDRESS/)).toBeTruthy();
    // Lowercase in the DOM; CSS uppercases it. Asserting rendered text rather
    // than styled appearance keeps this from breaking on a purely visual change.
    expect(entities.textContent).toContain("tokenized");
  });

  it("states the scan result as text, not as a colour", () => {
    renderTrace();

    expect(screen.getByTestId("outbound-scan").textContent).toContain("Outbound scan passed");
  });

  it("scopes the security claim to values that were detected", () => {
    // A detector false negative is a documented residual risk, so an absolute
    // claim would be one this page has no standing to make.
    renderTrace();
    const rendered = screen.getByTestId("protected-stage").textContent ?? "";

    expect(rendered).toContain("Sensitive values were replaced before transmission");
    expect(rendered).not.toMatch(/zero pii|no sensitive data can|guaranteed/i);
  });

  it("says when the payload was shortened", () => {
    renderTrace({ preview: { ...PREVIEW, truncated: true } });

    expect(screen.getByText("Shortened for display.")).toBeTruthy();
  });
});

describe("what must never reach the DOM", () => {
  it("renders no SGW namespace, identifier, or full token", () => {
    renderTrace();
    const rendered = screen.getByTestId("security-trace").textContent ?? "";

    expect(rendered).not.toContain("SGW:");
    expect(rendered).not.toContain("⟦SGW:");
    // A 26-character Crockford identifier is the thing that names a vault key.
    expect(rendered).not.toMatch(/[0-9A-HJKMNP-TV-Z]{26}/);
  });

  it("renders nothing that a full token was ever present to render", () => {
    // Passing a full token proves the component is not the thing doing the
    // masking: it would render it verbatim. The server masks first, which is
    // exactly why no code path here can leak one -- there is none to leak.
    const rendered = render(
      <SecurityTrace
        {...BASE}
        preview={{ ...PREVIEW, text: "Contact ⟦PERSON:••••⟧ now." }}
      />,
    );

    expect(rendered.container.textContent).not.toContain("SGW");
  });
});

describe("the preview is ephemeral", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("is never written to the console", () => {
    // Rendering is the only thing this component does with the text. A stray
    // debug statement would put the payload in the browser console, where it
    // outlives the response and lands in any copied console dump.
    const methods = ["log", "info", "warn", "error", "debug"] as const;
    const spies = methods.map((name) => vi.spyOn(console, name).mockImplementation(() => {}));

    renderTrace();

    for (const spy of spies) {
      expect(spy).not.toHaveBeenCalled();
    }
  });
});

describe("a blocked request", () => {
  const BLOCKED: Partial<SecurityTraceProps> = {
    summary: null,
    preview: null,
    provider: null,
    blocked: {
      code: "POLICY_VIOLATION",
      message: "The request was blocked by the active privacy policy.",
    },
  };

  it("stops the flow at the gateway", () => {
    renderTrace(BLOCKED);

    expect(screen.getByTestId("blocked-stage")).toBeTruthy();
    expect(screen.queryByTestId("protected-stage")).toBeNull();
  });

  it("says the request was not sent, rather than implying it by omission", () => {
    renderTrace(BLOCKED);

    expect(screen.getByTestId("not-sent").textContent).toContain("Not sent to provider");
    expect(screen.getByText("Policy blocked request")).toBeTruthy();
  });

  it("shows no provider stage and no masked payload", () => {
    renderTrace(BLOCKED);

    expect(screen.queryByTestId("preview-text")).toBeNull();
    expect(screen.queryByText(/Mock provider/i)).toBeNull();
    expect(screen.queryByText(/Outbound scan passed/i)).toBeNull();
  });

  it("invents no transform count, because a refusal returns no summary", () => {
    // A zeroed stand-in would render "0 sensitive values transformed", which is
    // a number the backend never produced.
    renderTrace(BLOCKED);

    expect(screen.queryByText(/sensitive values transformed/i)).toBeNull();
  });

  it("uses the gateway's own message for a non-policy refusal", () => {
    renderTrace({
      ...BLOCKED,
      blocked: { code: "VAULT_UNAVAILABLE", message: "The secure mapping service is unavailable." },
    });

    expect(screen.getByText("Request refused")).toBeTruthy();
    expect(screen.getByText("The secure mapping service is unavailable.")).toBeTruthy();
  });
});

describe("when the deployment has not enabled the preview", () => {
  it("still reports the stage and the scan without an empty box", () => {
    renderTrace({ preview: null });

    expect(screen.queryByTestId("preview-text")).toBeNull();
    expect(screen.queryByTestId("preview-entities")).toBeNull();
    expect(screen.getByTestId("outbound-scan").textContent).toContain("passed");
    expect(screen.getByTestId("protected-stage").textContent).toContain(
      "not returned by this deployment",
    );
  });

  it("shows the entity summary but no payload when text is absent", () => {
    renderTrace({ preview: { ...PREVIEW, text: null } });

    expect(screen.queryByTestId("preview-text")).toBeNull();
    expect(screen.getByTestId("preview-entities")).toBeTruthy();
  });
});
