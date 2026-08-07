"use client";

/**
 * Compact metric cards, entity badges, and the small diagnostic rows.
 *
 * Every value rendered here arrives from the API response or is measured by
 * this client; nothing is synthesised. `MetricCard` shows an em dash when a
 * value is absent rather than hiding the card, because "we do not have this"
 * is itself information -- policy version, for instance, is not on any v1
 * response, so it is permanently a dash and that is the honest report.
 */

export function MetricCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string | null;
  hint?: string;
}) {
  return (
    <div className="rounded-md border border-edge bg-surface px-2.5 py-2">
      <dt className="text-[10px] font-medium uppercase tracking-wide text-muted">{label}</dt>
      <dd className="mt-0.5 truncate text-sm font-semibold text-ink" title={hint ?? value ?? "—"}>
        {value ?? "—"}
      </dd>
    </div>
  );
}

/**
 * Entity type badges, showing the backend's own names verbatim.
 *
 * The names are not prettified. `EMAIL_ADDRESS` is what the detector called it
 * and what a policy rule keys on, so translating it to "Email address" would
 * put a second vocabulary between the operator and the system they are
 * configuring. The count is rendered as "× N" with the multiplication sign
 * inside the same element, so it is read as one label rather than two.
 */
export function EntityBadges({ types }: { types: Readonly<Record<string, number>> }) {
  const entries = Object.entries(types).sort(
    ([aName, aCount], [bName, bCount]) => bCount - aCount || aName.localeCompare(bName),
  );

  if (entries.length === 0) {
    return <p className="mt-2 text-xs text-muted">Nothing sensitive was found.</p>;
  }

  return (
    <ul className="mt-2 flex flex-wrap gap-1.5" data-testid="entity-badges">
      {entries.map(([type, count]) => (
        <li
          key={type}
          className="inline-flex items-center gap-1.5 rounded-full border border-protect/40
                     bg-protect/10 py-0.5 pl-2 pr-1 font-mono text-[10px] text-protect"
        >
          <span className="break-all">{type}</span>
          <span className="rounded-full bg-protect/20 px-1.5 py-px font-semibold tabular-nums">
            ×&nbsp;{count}
          </span>
        </li>
      ))}
    </ul>
  );
}

/**
 * A diagnostic row: long, uninteresting, and required when something goes
 * wrong. Values wrap rather than truncate -- a request id you cannot read in
 * full is a request id you cannot quote in a bug report.
 */
export function DiagnosticRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="grid grid-cols-[5.5rem_1fr] gap-2">
      <dt className="text-[11px] text-muted">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-[10px] leading-relaxed text-ink">
        {value ?? "—"}
      </dd>
    </div>
  );
}
