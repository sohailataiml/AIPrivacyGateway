import { describe, expect, it } from "vitest";

import {
  changeSummary,
  documentFrom,
  riskyChanges,
  type EntityRule,
  type PolicyVersion,
} from "./policies";

/**
 * The editing helpers, and the risk warnings that gate publishing.
 *
 * No fixture here restates a backend default. Every threshold in this file is
 * an arbitrary test value, and no test asserts that some entity type "should"
 * be 0.4 or 0.65 -- that number belongs to the detector, and a frontend test
 * pinning it would be the hardcoded catalog this phase exists to avoid.
 */

function rule(overrides: Partial<EntityRule> & { entity_type: string }): EntityRule {
  return {
    enabled: true,
    confidence_threshold: 0.5,
    action: "tokenize",
    priority: null,
    recognizer: null,
    description: null,
    ...overrides,
  };
}

const VERSION: PolicyVersion = {
  policy_name: "default",
  version: 3,
  status: "draft",
  is_active: false,
  created_at: "2026-08-07T10:00:00Z",
  published_at: null,
  name: "default",
  session_ttl_seconds: 1800,
  max_entities: 500,
  unknown_output_token_action: "preserve",
  providers: { mock: ["general-chat"] },
  entity_rules: [],
  entity_count: 0,
  enabled_entity_count: 0,
};

describe("documentFrom", () => {
  it("rebuilds a document the API will accept", () => {
    const document = documentFrom(VERSION, [
      rule({ entity_type: "EMAIL_ADDRESS", confidence_threshold: 0.7 }),
    ]);

    expect(document.schema_version).toBe(1);
    expect(document.providers).toEqual({ mock: { models: ["general-chat"] } });
    expect(document.entities.EMAIL_ADDRESS).toEqual({
      action: "tokenize",
      min_score: 0.7,
      enabled: true,
      priority: null,
      recognizer: null,
      description: null,
    });
  });

  it("carries settings through unchanged", () => {
    // An editor that silently rewrote the TTL would publish a change nobody made.
    const document = documentFrom(VERSION, []);

    expect(document.session_ttl_seconds).toBe(1800);
    expect(document.max_entities).toBe(500);
    expect(document.unknown_output_token_action).toBe("preserve");
  });
});

describe("riskyChanges", () => {
  it("warns when an action becomes less protective", () => {
    const before = [rule({ entity_type: "US_SSN", action: "block" })];
    const after = [rule({ entity_type: "US_SSN", action: "tokenize" })];

    const warnings = riskyChanges(before, after);

    expect(warnings).toHaveLength(1);
    expect(warnings[0]?.entityType).toBe("US_SSN");
    expect(warnings[0]?.reason).toContain("less protective");
  });

  it("warns on redact to allow and tokenize to allow", () => {
    const cases: Array<[EntityRule["action"], EntityRule["action"]]> = [
      ["redact", "allow"],
      ["tokenize", "allow"],
    ];

    for (const [from, to] of cases) {
      const risky = riskyChanges(
        [rule({ entity_type: "PERSON", action: from })],
        [rule({ entity_type: "PERSON", action: to })],
      );
      expect(risky).toHaveLength(1);
    }
  });

  it("does not warn when an action becomes more protective", () => {
    // Non-vacuity: the check is directional, not "any action change".
    const risky = riskyChanges(
      [rule({ entity_type: "US_SSN", action: "tokenize" })],
      [rule({ entity_type: "US_SSN", action: "block" })],
    );

    expect(risky).toEqual([]);
  });

  it("warns when a rule is disabled", () => {
    const risky = riskyChanges(
      [rule({ entity_type: "CREDIT_CARD" })],
      [rule({ entity_type: "CREDIT_CARD", enabled: false })],
    );

    expect(risky[0]?.reason).toBe("Rule disabled");
  });

  it("warns when a threshold rises enough to matter", () => {
    const risky = riskyChanges(
      [rule({ entity_type: "PHONE_NUMBER", confidence_threshold: 0.4 })],
      [rule({ entity_type: "PHONE_NUMBER", confidence_threshold: 0.7 })],
    );

    expect(risky[0]?.reason).toContain("fewer values match");
  });

  it("ignores a small threshold nudge", () => {
    const risky = riskyChanges(
      [rule({ entity_type: "PHONE_NUMBER", confidence_threshold: 0.4 })],
      [rule({ entity_type: "PHONE_NUMBER", confidence_threshold: 0.45 })],
    );

    expect(risky).toEqual([]);
  });

  it("does not warn when a threshold is lowered", () => {
    // Lowering catches more, which is the safe direction.
    const risky = riskyChanges(
      [rule({ entity_type: "PHONE_NUMBER", confidence_threshold: 0.7 })],
      [rule({ entity_type: "PHONE_NUMBER", confidence_threshold: 0.4 })],
    );

    expect(risky).toEqual([]);
  });

  it("warns when a rule is removed entirely", () => {
    const risky = riskyChanges([rule({ entity_type: "US_SSN" })], []);

    expect(risky[0]).toEqual({ entityType: "US_SSN", reason: "Rule removed" });
  });

  it("does not warn about a newly added rule", () => {
    const risky = riskyChanges([], [rule({ entity_type: "IP_ADDRESS" })]);

    expect(risky).toEqual([]);
  });
});

describe("changeSummary", () => {
  it("counts thresholds, actions, additions, and removals separately", () => {
    const before = [
      rule({ entity_type: "PERSON", confidence_threshold: 0.6 }),
      rule({ entity_type: "US_SSN", action: "block" }),
      rule({ entity_type: "LOCATION" }),
    ];
    const after = [
      rule({ entity_type: "PERSON", confidence_threshold: 0.8 }),
      rule({ entity_type: "US_SSN", action: "redact" }),
      rule({ entity_type: "IP_ADDRESS" }),
    ];

    const summary = changeSummary(before, after);

    expect(summary).toContain("1 threshold changed");
    expect(summary).toContain("1 action changed");
    expect(summary).toContain("1 entity added");
    expect(summary).toContain("1 entity removed");
  });

  it("is empty when nothing changed", () => {
    const rules = [rule({ entity_type: "PERSON" })];

    expect(changeSummary(rules, rules)).toEqual([]);
  });

  it("pluralises correctly", () => {
    const before = [rule({ entity_type: "A" }), rule({ entity_type: "B" })];
    const after = [
      rule({ entity_type: "A", confidence_threshold: 0.9 }),
      rule({ entity_type: "B", confidence_threshold: 0.9 }),
    ];

    expect(changeSummary(before, after)).toContain("2 thresholds changed");
  });
});
