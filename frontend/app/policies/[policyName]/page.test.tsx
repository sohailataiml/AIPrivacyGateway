import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { Suspense } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  catalogEntry,
  diff,
  rule,
  stubGateway,
  version,
  type GatewayStub,
  type Route,
} from "@/lib/testing";

import PolicyDetailPage from "./page";

vi.mock("next/navigation", () => ({ usePathname: () => "/policies/default" }));

/**
 * Policy detail: the draft lifecycle as an operator drives it.
 *
 * The fixtures are arbitrary. Nothing here asserts that a particular entity
 * type "should" have a particular threshold -- the page's contract is that it
 * renders and returns what the API gave it, and a fixture matching the real
 * defaults would pass even if the page substituted constants.
 */

const VERSIONS = "/api/v1/policies/default/versions";
const CATALOG = "/api/v1/detectors/entities";
const DRAFT = "/api/v1/policies/default/draft";
const PUBLISH = "/api/v1/policies/default/publish";
const VALIDATE = "/api/v1/policies/default/validate";
const DIFF = "/api/v1/policies/default/diff";

const PUBLISHED = version({
  version: 4,
  is_active: true,
  entity_rules: [
    rule({ entity_type: "EMAIL_ADDRESS", confidence_threshold: 0.72 }),
    rule({ entity_type: "US_SSN", action: "block", confidence_threshold: 0.51 }),
  ],
});

const OPEN_DRAFT = version({
  version: 5,
  status: "draft",
  is_active: false,
  published_at: null,
  entity_rules: PUBLISHED.entity_rules.map((r) => ({ ...r })),
});

let stub: GatewayStub | null = null;

afterEach(() => {
  stub?.restore();
  stub = null;
});

async function renderDetail(routes: readonly Route[]) {
  stub = stubGateway([
    { method: "GET", path: CATALOG, body: [catalogEntry({ entity_type: "IP_ADDRESS" })] },
    ...routes,
  ]);
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <PolicyDetailPage params={Promise.resolve({ policyName: "default" })} />
      </Suspense>,
    );
  });
  return stub;
}

const publishedOnly: Route[] = [{ method: "GET", path: VERSIONS, body: [PUBLISHED] }];
const withDraft: Route[] = [{ method: "GET", path: VERSIONS, body: [PUBLISHED, OPEN_DRAFT] }];

describe("viewing a published policy", () => {
  it("shows metadata from the active version", async () => {
    await renderDetail(publishedOnly);

    expect(await screen.findByText("1800s")).toBeTruthy();
    expect(screen.getByText("500")).toBeTruthy();
  });

  it("renders the rule table read-only when no draft is open", async () => {
    // Editing happens on a draft; the controls exist but refuse.
    await renderDetail(publishedOnly);
    await screen.findByTestId("entity-table");

    expect(
      (screen.getByLabelText("EMAIL_ADDRESS confidence threshold") as HTMLInputElement).disabled,
    ).toBe(true);
  });

  it("offers a create-draft button and no publish control", async () => {
    await renderDetail(publishedOnly);

    expect(await screen.findByRole("button", { name: "Create draft" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Publish…" })).toBeNull();
  });

  it("lists version history", async () => {
    await renderDetail(publishedOnly);

    expect(within(await screen.findByTestId("version-history")).getByText(/Version 4/)).toBeTruthy();
  });

  it("links to the playground", async () => {
    await renderDetail(publishedOnly);

    expect(
      (await screen.findByRole("link", { name: "Test playground" })).getAttribute("href"),
    ).toBe("/policies/default/test");
  });
});

describe("creating a draft", () => {
  it("posts to the draft endpoint and reloads", async () => {
    const gateway = await renderDetail(publishedOnly);
    (gateway as GatewayStub).restore();
    stub = stubGateway([
      { method: "GET", path: CATALOG, body: [] },
      { method: "POST", path: DRAFT, status: 201, body: OPEN_DRAFT },
      { method: "GET", path: VERSIONS, body: [PUBLISHED, OPEN_DRAFT] },
    ]);

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Create draft" }));
    });

    expect(stub.calls.some((c) => c.method === "POST" && c.url === DRAFT)).toBe(true);
    expect(await screen.findByTestId("policy-banner")).toBeTruthy();
  });
});

describe("editing a draft", () => {
  it("enables the controls once a draft is open", async () => {
    await renderDetail(withDraft);
    await screen.findByTestId("entity-table");

    expect(
      (screen.getByLabelText("EMAIL_ADDRESS confidence threshold") as HTMLInputElement).disabled,
    ).toBe(false);
  });

  it("keeps an edit in memory until it is saved", async () => {
    // Draft state is component state. Nothing is written to browser storage,
    // and nothing is sent until the operator saves.
    const gateway = await renderDetail(withDraft);
    await screen.findByTestId("entity-table");

    fireEvent.change(screen.getByLabelText("EMAIL_ADDRESS confidence threshold"), {
      target: { value: "0.9" },
    });

    expect(gateway.calls.every((c) => c.method !== "PATCH")).toBe(true);
    expect(
      (screen.getByLabelText("EMAIL_ADDRESS confidence threshold") as HTMLInputElement).value,
    ).toBe("0.9");
  });

  it("sends the whole edited document on save and validates it", async () => {
    const gateway = await renderDetail([
      ...withDraft,
      { method: "PATCH", path: DRAFT, body: OPEN_DRAFT },
      { method: "POST", path: VALIDATE, body: { valid: true, problems: [], warnings: [] } },
    ]);
    await screen.findByTestId("entity-table");
    fireEvent.change(screen.getByLabelText("EMAIL_ADDRESS confidence threshold"), {
      target: { value: "0.9" },
    });

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save & validate" }));
    });

    const patch = gateway.calls.find((c) => c.method === "PATCH");
    const document = (patch?.body as { document: { entities: Record<string, { min_score: number }> } })
      .document;
    expect(document.entities.EMAIL_ADDRESS?.min_score).toBe(0.9);
    expect(document.entities.US_SSN).toBeDefined();
  });

  it("surfaces validation problems returned by the backend", async () => {
    await renderDetail([
      ...withDraft,
      { method: "PATCH", path: DRAFT, body: OPEN_DRAFT },
      {
        method: "POST",
        path: VALIDATE,
        body: {
          valid: false,
          problems: [
            { field: "entities.NOPE", code: "unsupported_entity", message: "Unknown type." },
          ],
          warnings: [],
        },
      },
    ]);
    await screen.findByTestId("entity-table");

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save & validate" }));
    });

    expect((await screen.findByTestId("validation-problems")).textContent).toContain(
      "Unknown type.",
    );
  });

  it("adds an entity seeded from the detector catalog, not from a constant", async () => {
    await renderDetail(withDraft);
    await screen.findByTestId("entity-table");

    fireEvent.change(screen.getByLabelText("Add entity type"), {
      target: { value: "IP_ADDRESS" },
    });

    // 0.61 is the fixture's catalog default; the page must take it from there.
    expect(
      (screen.getByLabelText("IP_ADDRESS confidence threshold") as HTMLInputElement).value,
    ).toBe("0.61");
  });

  it("removes an entity from the draft", async () => {
    await renderDetail(withDraft);
    await screen.findByTestId("entity-table");

    fireEvent.click(
      within(screen.getByRole("row", { name: /US_SSN/ })).getByRole("button", { name: "Remove" }),
    );

    expect(screen.queryByLabelText("US_SSN action")).toBeNull();
  });

  it("discards a draft", async () => {
    const gateway = await renderDetail([
      ...withDraft,
      { method: "DELETE", path: DRAFT, status: 204 },
    ]);
    await screen.findByTestId("entity-table");

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Discard draft" }));
    });

    expect(gateway.calls.some((c) => c.method === "DELETE")).toBe(true);
  });
});

describe("publishing", () => {
  async function openDialog() {
    await renderDetail([
      ...withDraft,
      { method: "PATCH", path: DRAFT, body: OPEN_DRAFT },
      { method: "POST", path: PUBLISH, body: version({ version: 5, is_active: true }) },
    ]);
    await screen.findByTestId("entity-table");
  }

  it("asks for confirmation rather than publishing straight away", async () => {
    await openDialog();

    fireEvent.click(screen.getByRole("button", { name: "Publish…" }));

    expect(await screen.findByTestId("publish-dialog")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Publish policy version 5?" })).toBeTruthy();
  });

  it("summarises what will change", async () => {
    await openDialog();
    fireEvent.change(screen.getByLabelText("EMAIL_ADDRESS confidence threshold"), {
      target: { value: "0.9" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Publish…" }));

    expect((await screen.findByTestId("publish-summary")).textContent).toContain(
      "1 threshold changed",
    );
  });

  it("warns before publishing a weakened control", async () => {
    await openDialog();
    fireEvent.change(screen.getByLabelText("US_SSN action"), { target: { value: "allow" } });

    fireEvent.click(screen.getByRole("button", { name: "Publish…" }));

    expect((await screen.findByTestId("risky-changes")).textContent).toContain("US_SSN");
  });

  it("publishes only after the confirmation is clicked", async () => {
    await openDialog();
    fireEvent.click(screen.getByRole("button", { name: "Publish…" }));
    await screen.findByTestId("publish-dialog");

    expect(stub?.calls.some((c) => c.url === PUBLISH)).toBe(false);

    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-publish"));
    });

    expect(stub?.calls.some((c) => c.url === PUBLISH)).toBe(true);
  });

  it("confirms success and reloads the versions", async () => {
    await openDialog();
    fireEvent.click(screen.getByRole("button", { name: "Publish…" }));
    await screen.findByTestId("publish-dialog");

    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-publish"));
    });

    expect((await screen.findByTestId("policy-banner")).textContent).toContain(
      "Version 5 is now active.",
    );
  });
});

describe("diff", () => {
  it("fetches the comparison from the backend rather than computing it", async () => {
    // Two versions, because comparing needs a predecessor -- the button is
    // absent for a policy that has only ever had one version, which is correct.
    const gateway = await renderDetail([
      {
        method: "GET",
        path: VERSIONS,
        body: [version({ version: 3, is_active: false }), PUBLISHED],
      },
      { method: "GET", path: DIFF, body: diff({ from_version: 3, to_version: 4 }) },
    ]);
    await screen.findByTestId("version-history");

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Compare with v3/ }));
    });

    expect(gateway.calls.some((c) => c.url.startsWith(DIFF))).toBe(true);
    expect((await screen.findByTestId("diff-view")).textContent).toContain(
      "PHONE_NUMBER.min_score",
    );
  });
});

describe("failures", () => {
  it("shows the gateway's refusal", async () => {
    await renderDetail([
      {
        method: "GET",
        path: VERSIONS,
        status: 409,
        body: { error: { code: "POLICY_NOT_FOUND", message: "No such policy." } },
      },
    ]);

    expect((await screen.findByTestId("policy-banner")).textContent).toContain("No such policy.");
  });
});
