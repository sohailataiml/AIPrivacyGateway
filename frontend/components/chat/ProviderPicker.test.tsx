import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ProviderView } from "@/lib/gateway";

import { ProviderPicker, type ProviderPickerProps } from "./ProviderPicker";

/**
 * The selector's job is to offer only what the deployment can actually call.
 *
 * The list is backend-supplied, so these tests are mostly about what the
 * component does with an *unavailable* provider: it must neither hide it (which
 * looks like the feature not existing) nor let it be chosen (which produces a
 * guaranteed error), and it must never say why.
 */

const MOCK: ProviderView = { alias: "mock", kind: "mock", available: true, models: ["general-chat"] };
const OPENAI: ProviderView = { alias: "openai", kind: "external", available: true, models: ["fast"] };
const UNAVAILABLE: ProviderView = { ...OPENAI, available: false, models: [] };

const BASE: ProviderPickerProps = {
  providers: [MOCK, OPENAI],
  selected: "mock",
  onSelect: () => {},
  disabled: false,
};

function renderPicker(overrides: Partial<ProviderPickerProps> = {}) {
  return render(<ProviderPicker {...BASE} {...overrides} />);
}

describe("options", () => {
  it("offers every provider the backend reported", () => {
    renderPicker();

    expect(screen.getByRole("option", { name: /Mock/ })).toBeTruthy();
    expect(screen.getByRole("option", { name: /OpenAI/ })).toBeTruthy();
  });

  it("renders nothing at all when the backend reported none", () => {
    // A failed fetch leaves the demo working on the default rather than showing
    // an empty control that looks broken.
    const { container } = renderPicker({ providers: [] });

    expect(container.firstChild).toBeNull();
  });

  it("shows an unconfigured provider as disabled rather than hiding it", () => {
    renderPicker({ providers: [MOCK, UNAVAILABLE] });
    const option = screen.getByRole("option", { name: /OpenAI/ }) as HTMLOptionElement;

    expect(option.disabled).toBe(true);
    expect(option.textContent).toContain("not configured");
  });

  it("explains nothing about why a provider is unconfigured", () => {
    // Availability is a boolean; the reason is a fact about a credential.
    const { container } = renderPicker({ providers: [MOCK, UNAVAILABLE] });
    const rendered = (container.textContent ?? "").toLowerCase();

    for (const leak of ["api key", "api_key", "sk-", "secret", "environment", "env "]) {
      expect(rendered).not.toContain(leak);
    }
  });
});

describe("selection", () => {
  it("reports the chosen alias to the caller", () => {
    const onSelect = vi.fn();
    renderPicker({ onSelect });

    fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "openai" } });

    expect(onSelect).toHaveBeenCalledWith("openai");
  });

  it("is disabled while a request is in flight", () => {
    renderPicker({ disabled: true });

    expect((screen.getByLabelText("Provider") as HTMLSelectElement).disabled).toBe(true);
  });
});

describe("what kind of provider is selected", () => {
  it("marks an external provider without alarming language", () => {
    renderPicker({ selected: "openai" });
    const notice = screen.getByTestId("external-notice").textContent ?? "";

    expect(notice).toContain("External provider");
    // The gateway exists precisely so this case is handled; implying leakage
    // would misdescribe what the product does.
    expect(notice.toLowerCase()).not.toMatch(/your data is being shared|unsafe|warning|risk/);
  });

  it("says the mock is deterministic", () => {
    renderPicker({ selected: "mock" });

    expect(screen.getByTestId("mock-notice").textContent).toContain("Deterministic");
    expect(screen.queryByTestId("external-notice")).toBeNull();
  });

  it("takes the external/mock distinction from the backend, not the alias", () => {
    // `kind` is authoritative. A build that guessed from the name would get this
    // wrong the moment a deployment registered a differently-named adapter.
    renderPicker({
      providers: [{ alias: "house-model", kind: "external", available: true, models: [] }],
      selected: "house-model",
    });

    expect(screen.getByTestId("external-notice")).toBeTruthy();
  });
});
