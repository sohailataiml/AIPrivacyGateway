import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { EntityRule } from "@/lib/policies";

import { EntityTable } from "./EntityTable";

/**
 * The rule table.
 *
 * The values in this fixture are arbitrary test data, deliberately including a
 * PHONE_NUMBER threshold that is *not* the shipped default -- if the table ever
 * started rendering a hardcoded catalog value instead of the rule it was given,
 * these assertions would fail.
 */

const RULES: EntityRule[] = [
  {
    entity_type: "PHONE_NUMBER",
    enabled: true,
    confidence_threshold: 0.4,
    action: "tokenize",
    priority: 20,
    recognizer: "presidio-builtin",
    description: "Telephone numbers.",
  },
  {
    entity_type: "US_SSN",
    enabled: false,
    confidence_threshold: 0.5,
    action: "block",
    priority: null,
    recognizer: null,
    description: null,
  },
];

describe("rendering", () => {
  it("shows every column from the rule it was given", () => {
    render(<EntityTable rules={RULES} onChange={null} />);
    const row = screen.getByRole("row", { name: /PHONE_NUMBER/ });

    expect(within(row).getByText("PHONE_NUMBER")).toBeTruthy();
    expect(within(row).getByText("20")).toBeTruthy();
    expect(within(row).getByText("presidio-builtin")).toBeTruthy();
    expect(within(row).getByText("Telephone numbers.")).toBeTruthy();
  });

  it("renders the threshold it was given, not a default", () => {
    render(<EntityTable rules={RULES} onChange={null} />);

    const input = screen.getByLabelText("PHONE_NUMBER confidence threshold") as HTMLInputElement;
    expect(input.value).toBe("0.4");
  });

  it("shows an em dash for absent optional fields", () => {
    render(<EntityTable rules={RULES} onChange={null} />);
    const row = screen.getByRole("row", { name: /US_SSN/ });

    expect(within(row).getAllByText("—").length).toBe(3);
  });

  it("reflects the disabled state of a rule", () => {
    render(<EntityTable rules={RULES} onChange={null} />);

    expect((screen.getByLabelText("US_SSN enabled") as HTMLInputElement).checked).toBe(false);
  });

  it("says so plainly when a policy configures nothing", () => {
    render(<EntityTable rules={[]} onChange={null} />);

    expect(screen.getByText(/configures no entity rules/)).toBeTruthy();
  });
});

describe("read-only mode", () => {
  it("disables every control when no draft is open", () => {
    // Disabled rather than hidden: it teaches that edits happen on a draft.
    render(<EntityTable rules={RULES} onChange={null} />);

    expect((screen.getByLabelText("PHONE_NUMBER enabled") as HTMLInputElement).disabled).toBe(
      true,
    );
    expect((screen.getByLabelText("PHONE_NUMBER action") as HTMLSelectElement).disabled).toBe(
      true,
    );
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
  });
});

describe("editing", () => {
  it("reports a threshold edit without mutating the input array", () => {
    const onChange = vi.fn();
    const original = structuredClone(RULES);
    render(<EntityTable rules={RULES} onChange={onChange} />);

    fireEvent.change(screen.getByLabelText("PHONE_NUMBER confidence threshold"), {
      target: { value: "0.75" },
    });

    expect(onChange).toHaveBeenCalledTimes(1);
    const [next] = onChange.mock.calls[0] as [EntityRule[]];
    expect(next[0]?.confidence_threshold).toBe(0.75);
    expect(RULES).toEqual(original);
  });

  it("reports an action change", () => {
    const onChange = vi.fn();
    render(<EntityTable rules={RULES} onChange={onChange} />);

    fireEvent.change(screen.getByLabelText("US_SSN action"), { target: { value: "redact" } });

    const [next] = onChange.mock.calls[0] as [EntityRule[]];
    expect(next[1]?.action).toBe("redact");
  });

  it("offers every action the backend supports", () => {
    render(<EntityTable rules={RULES} onChange={vi.fn()} />);
    const select = screen.getByLabelText("US_SSN action");

    const options = within(select).getAllByRole("option").map((o) => o.textContent);
    expect(new Set(options)).toEqual(
      new Set(["allow", "tokenize", "redact", "pseudonymize", "block"]),
    );
  });

  it("reports an enable toggle", () => {
    const onChange = vi.fn();
    render(<EntityTable rules={RULES} onChange={onChange} />);

    fireEvent.click(screen.getByLabelText("US_SSN enabled"));

    const [next] = onChange.mock.calls[0] as [EntityRule[]];
    expect(next[1]?.enabled).toBe(true);
  });

  it("reports a removal", () => {
    const onRemove = vi.fn();
    render(<EntityTable rules={RULES} onChange={vi.fn()} onRemove={onRemove} />);

    fireEvent.click(within(screen.getByRole("row", { name: /US_SSN/ })).getByRole("button"));

    expect(onRemove).toHaveBeenCalledWith("US_SSN");
  });
});

describe("layout and accessibility", () => {
  it("scrolls inside its own container rather than widening the page", () => {
    const { container } = render(<EntityTable rules={RULES} onChange={null} />);

    expect(container.querySelector(".overflow-x-auto")).toBeTruthy();
  });

  it("labels every interactive control", () => {
    render(<EntityTable rules={RULES} onChange={vi.fn()} />);

    for (const rule of RULES) {
      expect(screen.getByLabelText(`${rule.entity_type} enabled`)).toBeTruthy();
      expect(screen.getByLabelText(`${rule.entity_type} action`)).toBeTruthy();
      expect(screen.getByLabelText(`${rule.entity_type} confidence threshold`)).toBeTruthy();
    }
  });

  it("uses row headers so a screen reader can announce the entity type", () => {
    render(<EntityTable rules={RULES} onChange={null} />);

    expect(screen.getByRole("rowheader", { name: "PHONE_NUMBER" })).toBeTruthy();
  });
});
