import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { getApiKey, hasApiKey, setApiKey, clearApiKey } from "./credential";

/**
 * ADR-0019: nothing sensitive is persisted in the browser.
 *
 * A component test cannot prove this -- it only exercises the paths it happens
 * to call. So this reads the source instead and asserts the APIs are absent
 * altogether, which is the difference between "we did not persist anything this
 * time" and "there is no code that could".
 *
 * If a future feature genuinely needs one of these (a theme preference, say),
 * this test should be narrowed to the specific file and key rather than
 * deleted. Deleting it removes the only enforcement.
 */

const ROOT = join(__dirname, "..");
const SKIP = new Set(["node_modules", ".next", ".git", "out", "coverage"]);
/**
 * Matched against *usage*, not mention.
 *
 * The earlier version matched the bare identifier, which flagged a comment
 * explaining that the playground never writes its input to localStorage --
 * prose describing the guarantee tripped the guard enforcing it. Requiring a
 * property access or call keeps every real use caught while letting the code
 * say what it does not do. `foo.localStorage` cannot slip past either: the
 * word boundary still anchors the identifier.
 */
const FORBIDDEN = [
  { pattern: /\blocalStorage\s*[.[]/, why: "localStorage" },
  { pattern: /\bsessionStorage\s*[.[]/, why: "sessionStorage" },
  { pattern: /\bindexedDB\s*[.[(]/i, why: "IndexedDB" },
  { pattern: /\bdocument\.cookie\b/, why: "cookies" },
  { pattern: /\bnavigator\.sendBeacon\s*\(/, why: "beacon analytics" },
];

function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      found.push(...sourceFiles(full));
    } else if ([".ts", ".tsx"].includes(extname(entry)) && !entry.endsWith(".test.ts") && !entry.endsWith(".test.tsx")) {
      found.push(full);
    }
  }
  return found;
}

describe("browser persistence", () => {
  const files = sourceFiles(ROOT);

  it("finds source files to check", () => {
    // Non-vacuity: a broken walk would make every assertion below pass.
    expect(files.length).toBeGreaterThan(5);
  });

  for (const { pattern, why } of FORBIDDEN) {
    it(`never uses ${why}`, () => {
      const offenders = files.filter((file) => pattern.test(readFileSync(file, "utf8")));

      expect(offenders.map((f) => f.slice(ROOT.length + 1))).toEqual([]);
    });
  }

  it("still catches real usage after being narrowed to property access", () => {
    // Non-vacuity for every assertion above. Loosening the patterns to allow
    // prose is only safe if they still match code, so the code they must match
    // is written out here.
    const usages = [
      'localStorage.setItem("draft", text)',
      "localStorage['draft'] = text",
      "window.sessionStorage.setItem(k, v)",
      "indexedDB.open('drafts')",
      'document.cookie = "draft=" + text',
      "navigator.sendBeacon('/collect', prompt)",
    ];

    for (const usage of usages) {
      expect(FORBIDDEN.some(({ pattern }) => pattern.test(usage))).toBe(true);
    }
  });

  it("does not flag prose that merely names the APIs", () => {
    const prose = "// never written to localStorage, sessionStorage, or IndexedDB";

    expect(FORBIDDEN.some(({ pattern }) => pattern.test(prose))).toBe(false);
  });
});

describe("credential storage", () => {
  it("holds a pasted key in memory only", () => {
    setApiKey("sgw_live_abcdefgh_secret");

    expect(hasApiKey()).toBe(true);
    expect(getApiKey()).toBe("sgw_live_abcdefgh_secret");
    // The whole point: a reload loses it, because nothing wrote it anywhere.
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");

    clearApiKey();
    expect(hasApiKey()).toBe(false);
    expect(getApiKey()).toBeNull();
  });
});
