/**
 * The typed client for policy management.
 *
 * Every shape here mirrors what the API returns, and nothing here invents a
 * value. There is deliberately no default entity catalog, no default threshold
 * table, and no fallback policy: the backend is the only source of those, and a
 * frontend copy would drift the moment a detector changed. `PHONE_NUMBER` is
 * 0.40 in this system, but that number appears nowhere in this file -- it
 * arrives from `/v1/detectors/entities` and from the stored document.
 *
 * `action` is a union of the backend's own lowercase values rather than a
 * prettified enum, so a rule sent back is byte-identical to the rule received.
 */

import { request } from "@/lib/gateway";

export type EntityAction = "allow" | "tokenize" | "redact" | "pseudonymize" | "block";

export const ENTITY_ACTIONS: readonly EntityAction[] = [
  "allow",
  "tokenize",
  "redact",
  "pseudonymize",
  "block",
];

export interface EntityRule {
  entity_type: string;
  enabled: boolean;
  confidence_threshold: number;
  action: EntityAction;
  priority: number | null;
  recognizer: string | null;
  description: string | null;
}

export interface PolicyVersion {
  policy_name: string;
  version: number;
  status: "draft" | "published";
  is_active: boolean;
  created_at: string;
  published_at: string | null;
  name: string;
  session_ttl_seconds: number;
  max_entities: number;
  unknown_output_token_action: string;
  providers: Record<string, string[]>;
  entity_rules: EntityRule[];
  entity_count: number;
  enabled_entity_count: number;
}

export interface PolicySummary {
  policy_name: string;
  active_version: number | null;
  draft_version: number | null;
  status: string;
  last_published_at: string | null;
  version_count: number;
  entity_count: number;
  enabled_entity_count: number;
}

export interface ValidationProblem {
  field: string;
  code: string;
  message: string;
}

export interface PolicyValidationResult {
  valid: boolean;
  problems: ValidationProblem[];
  warnings: ValidationProblem[];
}

export interface FieldChange {
  path: string;
  before: string | null;
  after: string | null;
  kind: "added" | "removed" | "changed";
}

export interface PolicyDiff {
  policy_name: string;
  from_version: number;
  to_version: number;
  entity_changes: FieldChange[];
  setting_changes: FieldChange[];
  total_changes: number;
}

export interface DetectorCatalogEntry {
  entity_type: string;
  recognizer_type: string;
  default_threshold: number;
  severity: number;
  supported_actions: EntityAction[];
  description: string | null;
}

export interface PolicyTestSpan {
  entity_type: string;
  start: number;
  end: number;
  confidence: number;
  action: EntityAction;
  recognizer: string | null;
}

export interface PolicyTestResult {
  policy_name: string;
  version: number;
  policy_status: string;
  spans: PolicyTestSpan[];
  detected: number;
  entity_types: Record<string, number>;
  would_block: boolean;
}

/**
 * The stored document, as the API accepts it back.
 *
 * Kept as an opaque-ish record rather than a fully typed mirror: the document
 * schema is validated server-side with `extra="forbid"`, and a second
 * TypeScript definition of it would be one more thing to keep in step. The
 * editor reads a version, edits the rules it understands, and posts the whole
 * thing back.
 */
export interface PolicyDocument {
  schema_version: number;
  name: string;
  session_ttl_seconds: number;
  max_entities: number;
  providers: Record<string, { models: string[] }>;
  entities: Record<
    string,
    {
      action: EntityAction;
      min_score: number;
      enabled?: boolean;
      priority?: number | null;
      recognizer?: string | null;
      description?: string | null;
    }
  >;
  unknown_output_token_action: string;
}

export interface PolicyDraft {
  version: PolicyVersion;
  document: PolicyDocument;
}

// -- Reads --------------------------------------------------------------------
export function listPolicies(apiKey: string): Promise<PolicySummary[]> {
  return request<PolicySummary[]>("/v1/policies", { apiKey });
}

export function getPolicy(apiKey: string, name: string): Promise<PolicyVersion> {
  return request<PolicyVersion>(`/v1/policies/${encodeURIComponent(name)}`, { apiKey });
}

export function listVersions(apiKey: string, name: string): Promise<PolicyVersion[]> {
  return request<PolicyVersion[]>(`/v1/policies/${encodeURIComponent(name)}/versions`, {
    apiKey,
  });
}

export function getVersion(
  apiKey: string,
  name: string,
  version: number,
): Promise<PolicyVersion> {
  return request<PolicyVersion>(
    `/v1/policies/${encodeURIComponent(name)}/versions/${version}`,
    { apiKey },
  );
}

export function getDiff(
  apiKey: string,
  name: string,
  fromVersion: number,
  toVersion: number,
): Promise<PolicyDiff> {
  const query = new URLSearchParams({
    from_version: String(fromVersion),
    to_version: String(toVersion),
  });
  return request<PolicyDiff>(`/v1/policies/${encodeURIComponent(name)}/diff?${query}`, {
    apiKey,
  });
}

export function getDetectorCatalog(apiKey: string): Promise<DetectorCatalogEntry[]> {
  return request<DetectorCatalogEntry[]>("/v1/detectors/entities", { apiKey });
}

// -- Draft lifecycle ----------------------------------------------------------
export function createDraft(apiKey: string, name: string): Promise<PolicyVersion> {
  return request<PolicyVersion>(`/v1/policies/${encodeURIComponent(name)}/draft`, {
    method: "POST",
    apiKey,
  });
}

export function saveDraft(
  apiKey: string,
  name: string,
  document: PolicyDocument,
): Promise<PolicyVersion> {
  return request<PolicyVersion>(`/v1/policies/${encodeURIComponent(name)}/draft`, {
    method: "PATCH",
    apiKey,
    body: { document },
  });
}

export function discardDraft(apiKey: string, name: string): Promise<void> {
  return request<void>(`/v1/policies/${encodeURIComponent(name)}/draft`, {
    method: "DELETE",
    apiKey,
  });
}

export function validateDraft(
  apiKey: string,
  name: string,
): Promise<PolicyValidationResult> {
  return request<PolicyValidationResult>(
    `/v1/policies/${encodeURIComponent(name)}/validate`,
    { method: "POST", apiKey },
  );
}

export function publishDraft(apiKey: string, name: string): Promise<PolicyVersion> {
  return request<PolicyVersion>(`/v1/policies/${encodeURIComponent(name)}/publish`, {
    method: "POST",
    apiKey,
  });
}

// -- Playground ---------------------------------------------------------------
export function testPolicy(
  apiKey: string,
  input: { text: string; policyName: string; version?: number },
): Promise<PolicyTestResult> {
  return request<PolicyTestResult>("/v1/policies/test", {
    method: "POST",
    apiKey,
    body: {
      text: input.text,
      policy_name: input.policyName,
      ...(input.version === undefined ? {} : { version: input.version }),
    },
  });
}

// -- Editing helpers ----------------------------------------------------------
/**
 * Rebuild a document from a version plus edited rules.
 *
 * The version carries its rules flattened for display; the document wants them
 * keyed by entity type. Doing the conversion here rather than in a component
 * keeps the one place that knows both shapes findable.
 */
export function documentFrom(version: PolicyVersion, rules: EntityRule[]): PolicyDocument {
  return {
    schema_version: 1,
    name: version.name,
    session_ttl_seconds: version.session_ttl_seconds,
    max_entities: version.max_entities,
    providers: Object.fromEntries(
      Object.entries(version.providers).map(([alias, models]) => [alias, { models }]),
    ),
    entities: Object.fromEntries(
      rules.map((rule) => [
        rule.entity_type,
        {
          action: rule.action,
          min_score: rule.confidence_threshold,
          enabled: rule.enabled,
          priority: rule.priority,
          recognizer: rule.recognizer,
          description: rule.description,
        },
      ]),
    ),
    unknown_output_token_action: version.unknown_output_token_action,
  };
}

/** Changes worth an explicit warning before publishing. */
export interface RiskyChange {
  entityType: string;
  reason: string;
}

const PROTECTIVE_ORDER: Record<EntityAction, number> = {
  block: 4,
  redact: 3,
  pseudonymize: 2,
  tokenize: 1,
  allow: 0,
};

/** Raising a threshold by this much materially reduces what is caught. */
const THRESHOLD_JUMP = 0.2;

/**
 * Compare edited rules against the version they came from.
 *
 * Advisory only. The backend decides what is publishable; this exists so an
 * operator is told before, not after, that they are weakening a control.
 */
export function riskyChanges(original: EntityRule[], edited: EntityRule[]): RiskyChange[] {
  const before = new Map(original.map((rule) => [rule.entity_type, rule]));
  const risky: RiskyChange[] = [];

  for (const rule of edited) {
    const previous = before.get(rule.entity_type);
    if (previous === undefined) continue;

    if (previous.enabled && !rule.enabled) {
      risky.push({ entityType: rule.entity_type, reason: "Rule disabled" });
      continue;
    }
    if (PROTECTIVE_ORDER[rule.action] < PROTECTIVE_ORDER[previous.action]) {
      risky.push({
        entityType: rule.entity_type,
        reason: `${previous.action} → ${rule.action} is less protective`,
      });
    }
    if (rule.confidence_threshold - previous.confidence_threshold >= THRESHOLD_JUMP) {
      risky.push({
        entityType: rule.entity_type,
        reason: `Threshold raised ${previous.confidence_threshold} → ${rule.confidence_threshold}, so fewer values match`,
      });
    }
  }

  for (const rule of original) {
    if (!edited.some((candidate) => candidate.entity_type === rule.entity_type)) {
      risky.push({ entityType: rule.entity_type, reason: "Rule removed" });
    }
  }

  return risky;
}

/** A plain-language summary of what publishing would change. */
export function changeSummary(original: EntityRule[], edited: EntityRule[]): string[] {
  const before = new Map(original.map((rule) => [rule.entity_type, rule]));
  const after = new Map(edited.map((rule) => [rule.entity_type, rule]));

  const added = edited.filter((rule) => !before.has(rule.entity_type)).length;
  const removed = original.filter((rule) => !after.has(rule.entity_type)).length;

  let thresholds = 0;
  let actions = 0;
  let toggles = 0;
  for (const rule of edited) {
    const previous = before.get(rule.entity_type);
    if (previous === undefined) continue;
    if (previous.confidence_threshold !== rule.confidence_threshold) thresholds += 1;
    if (previous.action !== rule.action) actions += 1;
    if (previous.enabled !== rule.enabled) toggles += 1;
  }

  const lines: string[] = [];
  const changedRules = edited.filter((rule) => {
    const previous = before.get(rule.entity_type);
    return (
      previous !== undefined &&
      (previous.confidence_threshold !== rule.confidence_threshold ||
        previous.action !== rule.action ||
        previous.enabled !== rule.enabled)
    );
  }).length;

  if (changedRules > 0) lines.push(`${changedRules} entity rule${changedRules === 1 ? "" : "s"} changed`);
  if (thresholds > 0) lines.push(`${thresholds} threshold${thresholds === 1 ? "" : "s"} changed`);
  if (actions > 0) lines.push(`${actions} action${actions === 1 ? "" : "s"} changed`);
  if (toggles > 0) lines.push(`${toggles} rule${toggles === 1 ? "" : "s"} enabled or disabled`);
  if (added > 0) lines.push(`${added} entit${added === 1 ? "y" : "ies"} added`);
  if (removed > 0) lines.push(`${removed} entit${removed === 1 ? "y" : "ies"} removed`);
  return lines;
}
