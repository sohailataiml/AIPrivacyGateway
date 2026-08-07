import { vi } from "vitest";

import type {
  DetectorCatalogEntry,
  EntityRule,
  PolicyDiff,
  PolicySummary,
  PolicyTestResult,
  PolicyVersion,
} from "@/lib/policies";

/**
 * Fixtures and a fetch stub for the page tests.
 *
 * The fixtures are shaped like real API responses and are otherwise arbitrary.
 * In particular no threshold here is claimed to be "the" value for its entity
 * type: the point of these tests is that a page renders what the API sent, so
 * a fixture that matched the shipped default would pass even if the page
 * ignored the response and printed a constant.
 *
 * `stubGateway` routes by method and path rather than by call order, so a test
 * does not break when a page changes how many times it loads something.
 */

export function rule(overrides: Partial<EntityRule> & { entity_type: string }): EntityRule {
  return {
    enabled: true,
    confidence_threshold: 0.55,
    action: "tokenize",
    priority: null,
    recognizer: "presidio-builtin",
    description: null,
    ...overrides,
  };
}

export function version(overrides: Partial<PolicyVersion> = {}): PolicyVersion {
  const rules = overrides.entity_rules ?? [
    rule({ entity_type: "EMAIL_ADDRESS", confidence_threshold: 0.72 }),
    rule({ entity_type: "US_SSN", action: "block", confidence_threshold: 0.51 }),
  ];
  return {
    policy_name: "default",
    version: 1,
    status: "published",
    is_active: true,
    created_at: "2026-08-01T09:00:00Z",
    published_at: "2026-08-01T09:00:00Z",
    name: "default",
    session_ttl_seconds: 1800,
    max_entities: 500,
    unknown_output_token_action: "preserve",
    providers: { mock: ["general-chat"] },
    entity_count: rules.length,
    enabled_entity_count: rules.filter((r) => r.enabled).length,
    ...overrides,
    entity_rules: rules,
  };
}

export function summary(overrides: Partial<PolicySummary> = {}): PolicySummary {
  return {
    policy_name: "default",
    active_version: 4,
    draft_version: null,
    status: "published",
    last_published_at: "2026-08-05T12:30:00Z",
    version_count: 4,
    entity_count: 6,
    enabled_entity_count: 5,
    ...overrides,
  };
}

export function catalogEntry(
  overrides: Partial<DetectorCatalogEntry> & { entity_type: string },
): DetectorCatalogEntry {
  return {
    recognizer_type: "presidio-builtin",
    default_threshold: 0.61,
    severity: 40,
    supported_actions: ["allow", "tokenize", "redact", "pseudonymize", "block"],
    description: null,
    ...overrides,
  };
}

export function diff(overrides: Partial<PolicyDiff> = {}): PolicyDiff {
  const entity = overrides.entity_changes ?? [
    { path: "PHONE_NUMBER.min_score", before: "0.4", after: "0.6", kind: "changed" as const },
  ];
  const settings = overrides.setting_changes ?? [];
  return {
    policy_name: "default",
    from_version: 3,
    to_version: 4,
    total_changes: entity.length + settings.length,
    ...overrides,
    entity_changes: entity,
    setting_changes: settings,
  };
}

export function testResult(overrides: Partial<PolicyTestResult> = {}): PolicyTestResult {
  const spans = overrides.spans ?? [
    {
      entity_type: "EMAIL_ADDRESS",
      start: 8,
      end: 30,
      confidence: 0.88,
      action: "tokenize" as const,
      recognizer: null,
    },
  ];
  return {
    policy_name: "default",
    version: 4,
    policy_status: "published",
    detected: spans.length,
    entity_types: Object.fromEntries(
      spans.map((s) => [s.entity_type, spans.filter((o) => o.entity_type === s.entity_type).length]),
    ),
    would_block: spans.some((s) => s.action === "block"),
    ...overrides,
    spans,
  };
}

export interface Route {
  method?: string;
  /** Matched against the path, ignoring the query string. */
  path: string | RegExp;
  status?: number;
  body?: unknown;
}

export interface GatewayStub {
  calls: Array<{ method: string; url: string; body: unknown }>;
  restore: () => void;
}

/**
 * Replace `fetch` with a router over the supplied routes.
 *
 * An unmatched request rejects loudly rather than returning an empty 200: a
 * page quietly rendering nothing because a call went unstubbed is the failure
 * mode these tests exist to avoid.
 */
const REAL_FETCH = globalThis.fetch;
/**
 * Captured once, at module load, rather than per call.
 *
 * Capturing inside `stubGateway` restores whatever was installed at the time,
 * so a second stub in the same file would "restore" to the first stub and every
 * test after the first would talk to a router that no longer had its routes.
 */

export function stubGateway(routes: readonly Route[]): GatewayStub {
  const calls: GatewayStub["calls"] = [];

  const impl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const method = (init?.method ?? "GET").toUpperCase();
    const path = url.split("?")[0] ?? url;
    calls.push({
      method,
      url,
      body: init?.body === undefined ? undefined : JSON.parse(String(init.body)),
    });

    const match = routes.find(
      (route) =>
        (route.method ?? "GET").toUpperCase() === method &&
        (typeof route.path === "string" ? route.path === path : route.path.test(path)),
    );
    if (match === undefined) {
      throw new Error(`unstubbed request: ${method} ${url}`);
    }
    const status = match.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(match.body ?? null), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };

  globalThis.fetch = vi.fn(impl) as unknown as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = REAL_FETCH;
    },
  };
}
