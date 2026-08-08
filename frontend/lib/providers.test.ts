import { describe, expect, it } from "vitest";

import type { ProviderView } from "@/lib/gateway";

import { FALLBACK_MODEL, modelFor } from "./providers";

/**
 * The regression this file exists for: the provider became selectable while the
 * model stayed hardcoded, so choosing OpenAI sent `general-chat` and the policy
 * refused it with MODEL_NOT_ALLOWED. Nothing reached a provider, and the demo
 * dead-ended on an error that looked like a backend fault.
 */

const MOCK: ProviderView = {
  alias: "mock",
  kind: "mock",
  available: true,
  models: ["general-chat"],
};
const OPENAI: ProviderView = {
  alias: "openai",
  kind: "external",
  available: true,
  models: ["default", "fast"],
};

describe("modelFor", () => {
  it("sends a model the chosen provider's policy actually permits", () => {
    expect(modelFor([MOCK, OPENAI], "openai")).toBe("default");
    expect(modelFor([MOCK, OPENAI], "mock")).toBe("general-chat");
  });

  it("never sends one provider's alias to another", () => {
    // The exact defect: `general-chat` is the mock's alias and is not in the
    // external provider's allowlist.
    expect(modelFor([MOCK, OPENAI], "openai")).not.toBe("general-chat");
  });

  it("falls back only when the provider list has not loaded", () => {
    expect(modelFor([], "openai")).toBe(FALLBACK_MODEL);
  });

  it("falls back for an alias the backend did not report", () => {
    expect(modelFor([MOCK], "anthropic")).toBe(FALLBACK_MODEL);
  });

  it("falls back when a provider reports no permitted models", () => {
    // What an unavailable provider looks like: present, but with an empty
    // allowlist because the policy does not list it.
    expect(modelFor([{ ...OPENAI, available: false, models: [] }], "openai")).toBe(FALLBACK_MODEL);
  });
});
