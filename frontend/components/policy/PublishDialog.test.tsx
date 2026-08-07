import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { PolicyValidationResult, RiskyChange } from "@/lib/policies";

import { PublishDialog } from "./PublishDialog";

/**
 * The publish confirmation.
 *
 * Publishing changes what every subsequent request is protected by, so the
 * assertions that matter are the ones about *not* publishing: it never fires on
 * mount, it is blocked when the backend says the draft is invalid, and a risky
 * change is surfaced rather than silently accepted.
 */

const RISKY: RiskyChange[] = [
  { entityType: "US_SSN", reason: "block → tokenize is less protective" },
];

const INVALID: PolicyValidationResult = {
  valid: false,
  problems: [
    { field: "entities.FAVOURITE_COLOUR", code: "unsupported_entity", message: "Unknown type." },
  ],
  warnings: [],
};

function setup(props: Partial<React.ComponentProps<typeof PublishDialog>> = {}) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(
    <PublishDialog
      open
      version={5}
      summary={["3 entity rules changed", "1 entity added"]}
      risky={[]}
      validation={null}
      busy={false}
      onConfirm={onConfirm}
      onCancel={onCancel}
      {...props}
    />,
  );
  return { onConfirm, onCancel };
}

describe("confirmation", () => {
  it("names the version being published", () => {
    setup();

    expect(screen.getByRole("heading", { name: "Publish policy version 5?" })).toBeTruthy();
  });

  it("lists what will change", () => {
    setup();
    const summary = screen.getByTestId("publish-summary");

    expect(summary.textContent).toContain("3 entity rules changed");
    expect(summary.textContent).toContain("1 entity added");
  });

  it("does not publish without an explicit click", () => {
    const { onConfirm } = setup();

    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("publishes only on the confirm button", () => {
    const { onConfirm } = setup();

    fireEvent.click(screen.getByTestId("confirm-publish"));

    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("cancels without publishing", () => {
    const { onConfirm, onCancel } = setup();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(onCancel).toHaveBeenCalled();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("says so when a republish changes nothing", () => {
    setup({ summary: [] });

    expect(screen.getByText(/No rule changes/)).toBeTruthy();
  });
});

describe("risky changes", () => {
  it("warns before publishing a weakened control", () => {
    setup({ risky: RISKY });
    const warning = screen.getByTestId("risky-changes");

    expect(warning.textContent).toContain("US_SSN");
    expect(warning.textContent).toContain("less protective");
  });

  it("warns without blocking, because the change may be legitimate", () => {
    setup({ risky: RISKY });

    expect((screen.getByTestId("confirm-publish") as HTMLButtonElement).disabled).toBe(false);
  });

  it("shows no warning panel when nothing weakens", () => {
    setup();

    expect(screen.queryByTestId("risky-changes")).toBeNull();
  });
});

describe("validation", () => {
  it("blocks publishing when the backend rejected the draft", () => {
    // The backend is authoritative; this reflects its answer rather than
    // deciding for itself.
    setup({ validation: INVALID });

    expect((screen.getByTestId("confirm-publish") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("publish-blocked").textContent).toContain("Unknown type.");
  });

  it("allows publishing when validation passed", () => {
    setup({ validation: { valid: true, problems: [], warnings: [] } });

    expect((screen.getByTestId("confirm-publish") as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("busy state", () => {
  it("prevents a double publish while one is in flight", () => {
    setup({ busy: true });

    expect((screen.getByTestId("confirm-publish") as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("Publishing…")).toBeTruthy();
  });
});

describe("accessibility", () => {
  it("is a labelled dialog", () => {
    setup();

    expect(
      screen.getByRole("dialog", { hidden: true }).getAttribute("aria-labelledby"),
    ).toBe("publish-heading");
  });

  it("stays closed until asked", () => {
    setup({ open: false });

    expect(screen.getByRole("dialog", { hidden: true }).hasAttribute("open")).toBe(false);
  });
});
