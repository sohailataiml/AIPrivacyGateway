"use client";

/**
 * Where the API key lives: in a module-level variable, and nowhere else.
 *
 * ADR-0019 and architecture.md section 22.15 both say it plainly -- no API keys
 * in browser storage. So this holds the credential in memory for the life of
 * the tab and loses it on reload, which is the intended behaviour rather than a
 * limitation to be worked around later.
 *
 * It is a module variable rather than React state because the API client is not
 * a component and should not have to be handed a key through five layers of
 * props. Subscribers exist so the UI can react to a key arriving or being
 * cleared without that state being duplicated anywhere.
 */

let apiKey: string | null = null;
const subscribers = new Set<() => void>();

function notify(): void {
  for (const subscriber of subscribers) subscriber();
}

export function setApiKey(value: string): void {
  apiKey = value.trim() || null;
  notify();
}

export function clearApiKey(): void {
  apiKey = null;
  notify();
}

export function getApiKey(): string | null {
  return apiKey;
}

/** The first characters, for display. Never the whole key. */
export function apiKeyLabel(): string | null {
  if (!apiKey) return null;
  const prefix = apiKey.slice(0, 12);
  return `${prefix}\u2026`;
}

export function subscribe(listener: () => void): () => void {
  subscribers.add(listener);
  return () => {
    subscribers.delete(listener);
  };
}

/** Snapshot for ``useSyncExternalStore``. Presence only, never the value. */
export function hasApiKey(): boolean {
  return apiKey !== null;
}
