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
const FORBIDDEN = [
  { pattern: /\blocalStorage\b/, why: "localStorage" },
  { pattern: /\bsessionStorage\b/, why: "sessionStorage" },
  { pattern: /\bindexedDB\b/i, why: "IndexedDB" },
  { pattern: /\bdocument\.cookie\b/, why: "cookies" },
  { pattern: /\bnavigator\.sendBeacon\b/, why: "beacon analytics" },
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
