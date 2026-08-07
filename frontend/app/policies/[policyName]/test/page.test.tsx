import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { Suspense } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { stubGateway, testResult, type GatewayStub } from "@/lib/testing";

import PolicyTestPage from "./page";

vi.mock("next/navigation", () => ({ usePathname: () => "/policies/default/test" }));

/**
 * The policy test playground.
 *
 * Two properties are worth more than the rendering assertions: the page sends
 * the text to the API and never anywhere else, and it renders spans from
 * offsets because the API deliberately returns no matched substring. A test
 * that asserted highlighted text would be asserting a disclosure that does not
 * exist.
 */

const PATH = "/api/v1/policies/test";
let stub: GatewayStub | null = null;

afterEach(() => {
  stub?.restore();
  stub = null;
});

/**
 * Mount the page inside a Suspense boundary.
 *
 * The page reads its route params with `use()`, which suspends on first render.
 * Next supplies a boundary in the real app; a bare `render()` in a test has
 * none, so nothing mounts and every query fails with a message about the
 * element rather than about the missing boundary.
 */
async function renderPlayground(body: unknown, status = 200) {
  stub = stubGateway([{ method: "POST", path: PATH, status, body }]);
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <PolicyTestPage params={Promise.resolve({ policyName: "default" })} />
      </Suspense>,
    );
  });
  return stub;
}

async function run(): Promise<void> {
  fireEvent.click(await screen.findByRole("button", { name: "Run test" }));
}

describe("running a test", () => {
  it("sends the text and the policy name to the API", async () => {
    const gateway = await renderPlayground(testResult());
    const box = await screen.findByLabelText("Synthetic input");
    fireEvent.change(box, { target: { value: "Reach avery@example.test today." } });

    await run();
    await screen.findByTestId("span-table");

    expect(gateway.calls[0]?.body).toEqual({
      text: "Reach avery@example.test today.",
      policy_name: "default",
    });
  });

  it("reports which version answered, and whether it was a draft", async () => {
    await renderPlayground(testResult({ version: 7, policy_status: "draft" }));

    await run();

    expect(await screen.findByRole("heading", { name: /v7 \(draft\)/ })).toBeTruthy();
  });

  it("shows each span with offsets, confidence, and action", async () => {
    await renderPlayground(
      testResult({
        spans: [
          {
            entity_type: "EMAIL_ADDRESS",
            start: 6,
            end: 24,
            confidence: 0.88,
            action: "tokenize",
            recognizer: null,
          },
        ],
      }),
    );

    await run();
    const row = await screen.findByRole("row", { name: /EMAIL_ADDRESS/ });

    expect(within(row).getByText("6–24")).toBeTruthy();
    expect(within(row).getByText("0.88")).toBeTruthy();
    expect(within(row).getByText("tokenize")).toBeTruthy();
  });

  it("counts detections by type from the response", async () => {
    await renderPlayground(testResult({ detected: 3, entity_types: { PERSON: 2, US_SSN: 1 } }));

    await run();
    await screen.findByTestId("span-table");

    expect(screen.getByText("3")).toBeTruthy();
    expect(screen.getByText("PERSON")).toBeTruthy();
  });

  it("says so when nothing was detected", async () => {
    await renderPlayground(testResult({ spans: [], detected: 0, entity_types: {} }));

    await run();

    expect(await screen.findByText("Nothing sensitive was detected.")).toBeTruthy();
  });
});

describe("blocking", () => {
  it("says the provider would not be called", async () => {
    await renderPlayground(
      testResult({
        spans: [
          {
            entity_type: "US_SSN",
            start: 0,
            end: 11,
            confidence: 0.9,
            action: "block",
            recognizer: null,
          },
        ],
      }),
    );

    await run();
    const banner = await screen.findByTestId("would-block");

    expect(banner.textContent).toContain("Provider would NOT be called");
    expect(screen.queryByTestId("would-send")).toBeNull();
  });

  it("says the provider would be called when nothing blocks", async () => {
    // Non-vacuity: the banner is driven by the response, not always shown.
    await renderPlayground(testResult());

    await run();

    expect(await screen.findByTestId("would-send")).toBeTruthy();
    expect(screen.queryByTestId("would-block")).toBeNull();
  });
});

describe("disclosure", () => {
  it("renders spans without any matched text, because none is returned", async () => {
    const gateway = await renderPlayground(testResult());
    const secret = "avery.private@example.test";
    fireEvent.change(await screen.findByLabelText("Synthetic input"), {
      target: { value: `Contact ${secret} now.` },
    });

    await run();
    const table = await screen.findByTestId("span-table");

    // The text the operator typed is in the textarea and in the request, and
    // nowhere in the results.
    expect(table.textContent).not.toContain(secret);
    expect(gateway.calls[0]?.body).toMatchObject({ text: `Contact ${secret} now.` });
  });

  it("caps the input at the length the API accepts", async () => {
    await renderPlayground(testResult());

    const box = (await screen.findByLabelText("Synthetic input")) as HTMLTextAreaElement;
    expect(box.maxLength).toBe(20000);
  });
});

describe("failures", () => {
  it("shows the gateway's own refusal", async () => {
    await renderPlayground(
      { error: { code: "AUTHORIZATION_FAILED", message: "You are not allowed to do that." } },
      403,
    );

    await run();
    const error = await screen.findByTestId("test-error");

    expect(error.textContent).toContain("You are not allowed to do that.");
    expect(error.textContent).toContain("AUTHORIZATION_FAILED");
  });

  it("clears a stale result rather than leaving it beside an error", async () => {
    // A result from a previous policy shown next to a failure reads as though
    // the failed run produced it.
    stub = stubGateway([{ method: "POST", path: PATH, body: testResult({ version: 2 }) }]);
    await act(async () => {
      render(
        <Suspense fallback={null}>
          <PolicyTestPage params={Promise.resolve({ policyName: "default" })} />
        </Suspense>,
      );
    });
    await run();
    await screen.findByTestId("span-table");

    stub.restore();
    stub = stubGateway([
      { method: "POST", path: PATH, status: 409, body: { error: { code: "POLICY_NOT_FOUND", message: "Gone." } } },
    ]);
    await run();
    await screen.findByTestId("test-error");

    expect(screen.queryByTestId("span-table")).toBeNull();
  });
});

describe("accessibility", () => {
  it("labels the input and links back to the policy", async () => {
    await renderPlayground(testResult());

    expect(await screen.findByLabelText("Synthetic input")).toBeTruthy();
    expect(screen.getByRole("link", { name: "← default" }).getAttribute("href")).toBe(
      "/policies/default",
    );
  });

  it("refuses to run on empty input", async () => {
    await renderPlayground(testResult());
    fireEvent.change(await screen.findByLabelText("Synthetic input"), { target: { value: "  " } });

    expect((screen.getByRole("button", { name: "Run test" }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });
});
