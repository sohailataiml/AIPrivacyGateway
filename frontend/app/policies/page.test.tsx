import { render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { stubGateway, summary, type GatewayStub } from "@/lib/testing";

import PolicyListPage from "./page";

vi.mock("next/navigation", () => ({ usePathname: () => "/policies" }));

/**
 * The policy list page.
 *
 * Everything asserted here is a value the stub returned. No test claims a
 * particular entity count or version number is "correct" for the default
 * policy -- the page's job is to render what the API said, and a fixture
 * matching the real defaults would pass even if the page printed constants.
 */

let stub: GatewayStub | null = null;

afterEach(() => {
  stub?.restore();
  stub = null;
});

/**
 * Stub the listing call and mount the page.
 *
 * Rendering lives in the helper because the first version of this file stubbed
 * in every test and rendered in only one -- eleven tests then queried a page
 * that had never been mounted, and every failure read as "element not found"
 * rather than "you forgot to render".
 */
function renderList(body: unknown, status = 200) {
  stub = stubGateway([{ method: "GET", path: "/api/v1/policies", status, body }]);
  render(<PolicyListPage />);
  return stub;
}

describe("rendering", () => {
  it("shows a row per policy with counts from the response", async () => {
    renderList([summary({ policy_name: "clinical", entity_count: 9, enabled_entity_count: 7 })]);

    const row = await screen.findByText("clinical");
    const card = row.closest("a") as HTMLElement;
    expect(within(card).getByText("9")).toBeTruthy();
    expect(within(card).getByText("7")).toBeTruthy();
  });

  it("shows the active version", async () => {
    renderList([summary({ active_version: 12 })]);

    expect(await screen.findByText("Active v12")).toBeTruthy();
  });

  it("flags an open draft, because it changes what the buttons will do", async () => {
    renderList([summary({ draft_version: 13 })]);

    expect(await screen.findByText("Draft v13")).toBeTruthy();
  });

  it("shows no draft badge when there is none", async () => {
    renderList([summary({ draft_version: null })]);
    await screen.findByText("Active v4");

    expect(screen.queryByText(/^Draft v/)).toBeNull();
  });

  it("reports a policy that has never been published", async () => {
    renderList([summary({ last_published_at: null })]);

    expect(await screen.findByText("Never")).toBeTruthy();
  });

  it("links each policy to its detail page", async () => {
    renderList([summary({ policy_name: "clinical" })]);

    const link = (await screen.findByText("clinical")).closest("a");
    expect(link?.getAttribute("href")).toBe("/policies/clinical");
  });

  it("encodes a name that needs it", async () => {
    renderList([summary({ policy_name: "eu/gdpr" })]);

    const link = (await screen.findByText("eu/gdpr")).closest("a");
    expect(link?.getAttribute("href")).toBe("/policies/eu%2Fgdpr");
  });
});

describe("empty and error states", () => {
  it("says the tenant has no policies rather than showing an empty page", async () => {
    renderList([]);

    expect(await screen.findByText("This tenant has no policies.")).toBeTruthy();
  });

  it("surfaces a refusal with the gateway's own code", async () => {
    renderList(
      { error: { code: "AUTHORIZATION_FAILED", message: "You are not allowed to do that." } },
      403,
    );

    const error = await screen.findByTestId("policy-list-error");
    expect(error.textContent).toContain("You are not allowed to do that.");
    expect(error.textContent).toContain("AUTHORIZATION_FAILED");
  });

  it("does not claim the tenant has no policies when the request failed", async () => {
    // The two states look identical if a failure falls through to the empty
    // message, and an analyst would read "no policies" as a fact about their
    // tenant rather than as a permissions problem.
    renderList({ error: { code: "AUTHORIZATION_FAILED", message: "Nope." } }, 403);
    await screen.findByTestId("policy-list-error");

    expect(screen.queryByText("This tenant has no policies.")).toBeNull();
  });
});

describe("navigation", () => {
  it("offers both sections", async () => {
    renderList([summary()]);
    await screen.findByText("Active v4");

    const nav = screen.getByRole("navigation", { name: "Sections" });
    expect(within(nav).getByRole("link", { name: "Secure Chat" })).toBeTruthy();
    expect(within(nav).getByRole("link", { name: "Policies" })).toBeTruthy();
  });

  it("marks the current section for assistive technology", async () => {
    renderList([summary()]);
    await screen.findByText("Active v4");

    expect(
      screen.getByRole("link", { name: "Policies" }).getAttribute("aria-current"),
    ).toBe("page");
  });
});
