import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { diff, version } from "@/lib/testing";

import { DiffView, VersionHistory } from "./VersionHistory";

/**
 * Version history and diff rendering.
 *
 * Both are view-only. The assertions worth reading are that history offers no
 * way to edit a past version, and that the diff shows exactly what the backend
 * sent rather than anything computed here.
 */

const VERSIONS = [
  version({ version: 1, is_active: false, published_at: "2026-08-01T09:00:00Z" }),
  version({ version: 2, is_active: true, published_at: "2026-08-05T12:30:00Z" }),
  version({ version: 3, is_active: false, status: "draft", published_at: null }),
];

describe("VersionHistory", () => {
  it("lists newest first, because that is what an operator looks for", () => {
    render(<VersionHistory versions={VERSIONS} selected={null} onSelect={vi.fn()} />);

    const items = within(screen.getByTestId("version-history")).getAllByRole("button");
    expect(items[0]?.textContent).toContain("Version 3");
    expect(items[2]?.textContent).toContain("Version 1");
  });

  it("marks the active version", () => {
    render(<VersionHistory versions={VERSIONS} selected={null} onSelect={vi.fn()} />);

    const active = screen.getByRole("button", { name: /Version 2/ });
    expect(within(active).getByText("Active")).toBeTruthy();
  });

  it("marks an open draft", () => {
    render(<VersionHistory versions={VERSIONS} selected={null} onSelect={vi.fn()} />);

    expect(within(screen.getByRole("button", { name: /Version 3/ })).getByText("Draft")).toBeTruthy();
  });

  it("shows created and published times, and says so when unpublished", () => {
    render(<VersionHistory versions={VERSIONS} selected={null} onSelect={vi.fn()} />);
    const draft = screen.getByRole("button", { name: /Version 3/ });

    expect(draft.textContent).toContain("Created 2026-08-01 09:00:00 UTC");
    expect(draft.textContent).toContain("Published —");
  });

  it("reports entity counts per version", () => {
    render(<VersionHistory versions={VERSIONS} selected={null} onSelect={vi.fn()} />);

    expect(screen.getByRole("button", { name: /Version 2/ }).textContent).toContain(
      "2 rules · 2 enabled",
    );
  });

  it("marks the selected version for assistive technology, not only by colour", () => {
    render(<VersionHistory versions={VERSIONS} selected={2} onSelect={vi.fn()} />);

    expect(
      screen.getByRole("button", { name: /Version 2/ }).getAttribute("aria-current"),
    ).toBe("true");
  });

  it("reports a selection", () => {
    const onSelect = vi.fn();
    render(<VersionHistory versions={VERSIONS} selected={null} onSelect={onSelect} />);

    fireEvent.click(screen.getByRole("button", { name: /Version 1/ }));

    expect(onSelect).toHaveBeenCalledWith(1);
  });

  it("offers no editing control for a past version", () => {
    // View-only is the guarantee; a history entry is a button that selects,
    // and nothing else.
    render(<VersionHistory versions={VERSIONS} selected={null} onSelect={vi.fn()} />);

    expect(screen.queryByRole("textbox")).toBeNull();
    expect(screen.queryByRole("combobox")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });
});

describe("DiffView", () => {
  it("shows the version pair being compared", () => {
    render(<DiffView diff={diff()} />);

    expect(screen.getByRole("heading", { name: /v3.*v4/ })).toBeTruthy();
  });

  it("renders a threshold change with both values from the backend", () => {
    render(<DiffView diff={diff()} />);
    const view = screen.getByTestId("diff-view");

    expect(view.textContent).toContain("PHONE_NUMBER.min_score");
    expect(view.textContent).toContain("0.4");
    expect(view.textContent).toContain("0.6");
  });

  it("distinguishes added from removed entities", () => {
    render(
      <DiffView
        diff={diff({
          entity_changes: [
            { path: "IP_ADDRESS", before: null, after: "redact @ 0.5", kind: "added" },
            { path: "LOCATION", before: "tokenize @ 0.8", after: null, kind: "removed" },
          ],
        })}
      />,
    );
    const view = screen.getByTestId("diff-view");

    expect(view.textContent).toContain("added: redact @ 0.5");
    expect(view.textContent).toContain("removed: tokenize @ 0.8");
  });

  it("separates settings changes from entity changes", () => {
    render(
      <DiffView
        diff={diff({
          entity_changes: [],
          setting_changes: [
            { path: "session_ttl_seconds", before: "1800", after: "600", kind: "changed" },
          ],
        })}
      />,
    );

    expect(screen.getByRole("heading", { name: "Settings" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Entity rules" })).toBeNull();
  });

  it("says so plainly when two versions are identical", () => {
    render(<DiffView diff={diff({ entity_changes: [], setting_changes: [] })} />);

    expect(screen.getByText("These versions are identical.")).toBeTruthy();
  });

  it("conveys direction in text as well as with an arrow glyph", () => {
    // The arrow is aria-hidden, so the change needs a readable equivalent.
    render(<DiffView diff={diff()} />);

    expect(screen.getByText("changed to")).toBeTruthy();
  });
});
