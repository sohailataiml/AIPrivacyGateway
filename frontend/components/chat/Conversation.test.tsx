import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Conversation, type Turn } from "./Conversation";

/**
 * The response label carries the product's central claim.
 *
 * "LLM Response (Restored)" says the tokens sent upstream have been swapped
 * back, so what is on screen is not what the provider saw. The previous
 * rendering led with the provider's own "Mock provider reply: ..." text, which
 * read as though the gateway itself were a mock.
 */

const GATEWAY_TURN: Turn = {
  id: "t1",
  author: "gateway",
  text: "The referral concerns jane.doe@acme.internal.",
  provider: "mock",
  restored: 3,
};

describe("gateway turns", () => {
  it("labels the answer as restored", () => {
    render(<Conversation turns={[GATEWAY_TURN]} />);

    expect(screen.getByText("LLM Response (Restored)")).toBeTruthy();
  });

  it("demotes the mock provider to a secondary badge", () => {
    render(<Conversation turns={[GATEWAY_TURN]} />);

    const badge = screen.getByText("Mock provider");
    expect(badge.tagName).toBe("SPAN");
    // Secondary, not the heading for the turn.
    expect(badge.className).toContain("text-muted");
  });

  it("shows the restored count from the response", () => {
    render(<Conversation turns={[GATEWAY_TURN]} />);

    expect(screen.getByText("3 restored")).toBeTruthy();
  });

  it("omits the restored badge when nothing was restored", () => {
    render(<Conversation turns={[{ ...GATEWAY_TURN, restored: 0 }]} />);

    expect(screen.queryByText(/restored$/)).toBeNull();
  });

  it("names a non-mock provider as itself", () => {
    render(<Conversation turns={[{ ...GATEWAY_TURN, provider: "openai" }]} />);

    expect(screen.getByText("openai")).toBeTruthy();
    expect(screen.queryByText("Mock provider")).toBeNull();
  });
});

describe("rendering safety", () => {
  it("renders model output as text, never as markup", () => {
    // The one string on this page whose content an upstream model chose.
    const hostile = "<img src=x onerror=alert(1)> **not bold**";
    render(<Conversation turns={[{ ...GATEWAY_TURN, text: hostile }]} />);

    expect(screen.getByText(hostile)).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("wraps long unbroken text instead of overflowing", () => {
    render(<Conversation turns={[{ ...GATEWAY_TURN, text: "x".repeat(300) }]} />);

    expect(screen.getByText("x".repeat(300)).className).toContain("break-words");
  });
});

describe("structure", () => {
  it("presents the conversation as a labelled list", () => {
    render(<Conversation turns={[GATEWAY_TURN]} />);

    expect(screen.getByRole("list", { name: "Conversation" })).toBeTruthy();
  });

  it("invites a first prompt when empty", () => {
    render(<Conversation turns={[]} />);

    expect(screen.getByText(/Send a prompt/)).toBeTruthy();
  });
});
