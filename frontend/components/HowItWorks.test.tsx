import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { HowItWorks } from "./HowItWorks";

describe("HowItWorks", () => {
  it("stays closed until asked", () => {
    render(<HowItWorks open={false} onClose={() => {}} />);

    expect(screen.getByRole("dialog", { hidden: true }).hasAttribute("open")).toBe(false);
  });

  it("shows the documented flow when open", () => {
    render(<HowItWorks open onClose={() => {}} />);
    const dialog = screen.getByRole("dialog", { hidden: true });

    expect(dialog.hasAttribute("open")).toBe(true);
    for (const step of ["Upload", "Encrypt", "Detect", "Protect", "Outbound scan", "Restore"]) {
      expect(dialog.textContent).toContain(step);
    }
  });

  it("closes on the close button", () => {
    const onClose = vi.fn();
    render(<HowItWorks open onClose={onClose} />);

    fireEvent.click(screen.getByRole("button", { name: "Close" }));

    expect(onClose).toHaveBeenCalled();
  });

  it("is labelled for assistive technology", () => {
    render(<HowItWorks open onClose={() => {}} />);

    expect(screen.getByRole("heading", { name: "How it works" })).toBeTruthy();
    expect(
      screen.getByRole("dialog", { hidden: true }).getAttribute("aria-labelledby"),
    ).toBe("how-it-works-heading");
  });

  it("presents the flow as an ordered list so order is conveyed structurally", () => {
    render(<HowItWorks open onClose={() => {}} />);

    expect(screen.getByRole("dialog", { hidden: true }).querySelector("ol")).toBeTruthy();
  });
});
