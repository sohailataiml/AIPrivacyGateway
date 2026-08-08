import type { ProviderView } from "@/lib/gateway";

/**
 * Choosing the model alias to send for a given provider.
 *
 * Model aliases are per-provider and policy-scoped: the mock answers to
 * `general-chat`, the external adapter to `default`/`fast`. Sending one
 * provider's alias to another is refused by the policy's model allowlist before
 * anything is transmitted -- correct behaviour, and a confusing dead end for a
 * demo. That is precisely what shipped when the provider became selectable and
 * the model stayed hardcoded: picking OpenAI produced "The requested model is
 * not permitted" and no request ever left the gateway.
 *
 * The permitted list comes from `GET /v1/providers`, so this reports what the
 * caller's policy actually allows rather than guessing from the alias.
 */

export const FALLBACK_MODEL = "general-chat";
/** Used only before the provider list has loaded, or for an alias absent from it. */

export function modelFor(providers: readonly ProviderView[], alias: string): string {
  const models = providers.find((row) => row.alias === alias)?.models ?? [];
  return models[0] ?? FALLBACK_MODEL;
}
