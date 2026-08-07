"use client";

import type { FieldChange, PolicyDiff, PolicyVersion } from "@/lib/policies";

/**
 * Version history and the diff between two stored versions.
 *
 * Both are view-only, and the diff is fetched from the backend rather than
 * computed here. Reconstructing historical policy state in a browser would mean
 * the UI could disagree with the database about what version 3 contained --
 * and the whole value of an immutable version is that there is one answer.
 */

function formatTime(value: string | null): string {
  if (value === null) return "—";
  // Locale-independent and stable across environments: a test that renders in
  // one timezone and asserts in another should not be flaky.
  return value.replace("T", " ").replace(/\.\d+/, "").replace("Z", " UTC");
}

export function VersionHistory({
  versions,
  selected,
  onSelect,
}: {
  versions: readonly PolicyVersion[];
  selected: number | null;
  onSelect: (version: number) => void;
}) {
  return (
    <ol className="space-y-1" data-testid="version-history">
      {[...versions].reverse().map((version) => {
        const isSelected = selected === version.version;
        return (
          <li key={version.version}>
            <button
              type="button"
              onClick={() => onSelect(version.version)}
              aria-current={isSelected ? "true" : undefined}
              className={`w-full rounded-md border px-3 py-2 text-left transition focus:outline-none
                focus:ring-2 focus:ring-accent ${
                  isSelected ? "border-accent bg-accent/10" : "border-edge hover:border-accent/50"
                }`}
            >
              <span className="flex flex-wrap items-baseline gap-2">
                <span className="text-xs font-semibold text-ink">
                  Version {version.version}
                </span>
                {version.is_active ? (
                  <span className="rounded border border-protect/40 bg-protect/10 px-1.5 py-0.5 text-[10px] text-protect">
                    Active
                  </span>
                ) : null}
                {version.status === "draft" ? (
                  <span className="rounded border border-warn/40 bg-warn/10 px-1.5 py-0.5 text-[10px] text-warn">
                    Draft
                  </span>
                ) : null}
              </span>
              <span className="mt-1 block text-[10px] text-muted">
                {version.entity_count} rules · {version.enabled_entity_count} enabled
              </span>
              <span className="block text-[10px] text-muted">
                Created {formatTime(version.created_at)}
              </span>
              <span className="block text-[10px] text-muted">
                Published {formatTime(version.published_at)}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function ChangeRow({ change }: { change: FieldChange }) {
  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 py-1">
      <span className="font-mono text-[11px] text-ink">{change.path}</span>
      {change.kind === "added" ? (
        <span className="text-[11px] text-protect">added: {change.after}</span>
      ) : change.kind === "removed" ? (
        <span className="text-[11px] text-danger">removed: {change.before}</span>
      ) : (
        <span className="font-mono text-[11px] text-muted">
          {change.before} <span aria-hidden>→</span>{" "}
          <span className="text-ink">{change.after}</span>
          <span className="sr-only">changed to</span>
        </span>
      )}
    </li>
  );
}

export function DiffView({ diff }: { diff: PolicyDiff }) {
  return (
    <section aria-labelledby="diff-heading" data-testid="diff-view">
      <h3 id="diff-heading" className="text-xs font-semibold text-ink">
        v{diff.from_version} <span aria-hidden>→</span> v{diff.to_version}
      </h3>
      {diff.total_changes === 0 ? (
        <p className="mt-2 text-xs text-muted">These versions are identical.</p>
      ) : (
        <>
          {diff.entity_changes.length > 0 ? (
            <div className="mt-2">
              <h4 className="text-[10px] uppercase tracking-wide text-muted">Entity rules</h4>
              <ul className="mt-1 divide-y divide-edge/60">
                {diff.entity_changes.map((change) => (
                  <ChangeRow key={`${change.path}-${change.kind}`} change={change} />
                ))}
              </ul>
            </div>
          ) : null}
          {diff.setting_changes.length > 0 ? (
            <div className="mt-3">
              <h4 className="text-[10px] uppercase tracking-wide text-muted">Settings</h4>
              <ul className="mt-1 divide-y divide-edge/60">
                {diff.setting_changes.map((change) => (
                  <ChangeRow key={`${change.path}-${change.kind}`} change={change} />
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}
    </section>
  );
}
