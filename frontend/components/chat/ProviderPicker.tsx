"use client";

import type { ProviderView } from "@/lib/gateway";

/**
 * Which model answers. Nothing else.
 *
 * The point this control makes in a demo is that it makes *no* difference to
 * anything that matters: the same detection, the same policy, the same
 * tokenization, the same outbound scan run either way, and the provider adapter
 * is reached only after all of them. Switching from the deterministic mock to a
 * real model and watching the privacy stages stay identical is the argument.
 *
 * **The list comes from the backend.** A hardcoded list would offer a provider
 * whose credential is absent -- a control whose only outcome is an error -- and
 * would hide one a deployment added. `GET /v1/providers` reports what is both
 * registered and permitted by the caller's policy.
 *
 * **Unavailable options are disabled, not hidden.** "Not configured" tells an
 * operator that the provider exists and the deployment has not set it up, which
 * is actionable. Silently omitting it looks identical to the feature not
 * existing. What is never shown is *why*: that is a fact about a credential.
 */

const EXTERNAL = "external";

export interface ProviderPickerProps {
  providers: readonly ProviderView[];
  selected: string;
  onSelect: (alias: string) => void;
  disabled: boolean;
}

function labelFor(provider: ProviderView): string {
  if (provider.alias === "mock") return "Mock";
  if (provider.alias === "openai") return "OpenAI";
  // An alias this build has no display name for is shown verbatim rather than
  // prettified into a second vocabulary the backend does not use.
  return provider.alias;
}

export function ProviderPicker({ providers, selected, onSelect, disabled }: ProviderPickerProps) {
  if (providers.length === 0) return null;

  const active = providers.find((provider) => provider.alias === selected) ?? null;

  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="provider-picker">
      <label htmlFor="provider" className="text-[11px] uppercase tracking-wide text-muted">
        Provider
      </label>
      <select
        id="provider"
        className="field w-auto py-1 text-xs"
        value={selected}
        disabled={disabled}
        onChange={(event) => onSelect(event.target.value)}
      >
        {providers.map((provider) => (
          <option key={provider.alias} value={provider.alias} disabled={!provider.available}>
            {labelFor(provider)}
            {provider.available ? "" : " — not configured"}
          </option>
        ))}
      </select>

      {/* Text, not a colour or an icon. Stated plainly and without alarm: the
          whole point of the gateway is that this case is handled. */}
      {active?.kind === EXTERNAL ? (
        <span
          className="rounded border border-edge px-1.5 py-0.5 text-[10px] text-muted"
          data-testid="external-notice"
        >
          External provider · receives protected text only
        </span>
      ) : (
        <span className="text-[10px] text-muted" data-testid="mock-notice">
          Deterministic demo provider
        </span>
      )}
    </div>
  );
}
