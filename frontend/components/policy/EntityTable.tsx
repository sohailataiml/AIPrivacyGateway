"use client";

import { ENTITY_ACTIONS, type EntityAction, type EntityRule } from "@/lib/policies";

/**
 * The entity rule table, read-only or editable depending on whether a draft is
 * open.
 *
 * Every value shown comes from the version the caller loaded. There is no
 * default threshold and no default action in this file: a rule that arrives
 * with a threshold of 0.4 renders 0.4, and if the backend ever changes what it
 * ships, this table changes with it and nothing here needs editing.
 *
 * Editing is disabled rather than hidden when there is no draft. A greyed
 * control that explains itself teaches the workflow -- edits happen on a
 * draft -- where a missing one just looks like a feature that is absent.
 */

export interface EntityTableProps {
  rules: readonly EntityRule[];
  /** Null when viewing a published version; a callback when a draft is open. */
  onChange: ((rules: EntityRule[]) => void) | null;
  onRemove?: (entityType: string) => void;
}

const ACTION_TONE: Record<EntityAction, string> = {
  block: "text-danger",
  redact: "text-warn",
  pseudonymize: "text-accent",
  tokenize: "text-protect",
  allow: "text-muted",
};

export function EntityTable({ rules, onChange, onRemove }: EntityTableProps) {
  const editable = onChange !== null;

  function update(entityType: string, patch: Partial<EntityRule>): void {
    if (onChange === null) return;
    onChange(
      rules.map((rule) => (rule.entity_type === entityType ? { ...rule, ...patch } : rule)),
    );
  }

  if (rules.length === 0) {
    return <p className="p-4 text-xs text-muted">This policy configures no entity rules.</p>;
  }

  return (
    // Scrolls inside its own container so a narrow viewport never gives the
    // page a horizontal scrollbar.
    <div className="overflow-x-auto">
      <table className="w-full min-w-[46rem] border-collapse text-xs" data-testid="entity-table">
        <caption className="sr-only">Entity rules for this policy version</caption>
        <thead>
          <tr className="border-b border-edge text-left text-[10px] uppercase tracking-wide text-muted">
            <th scope="col" className="px-3 py-2 font-medium">Enabled</th>
            <th scope="col" className="px-3 py-2 font-medium">Entity type</th>
            <th scope="col" className="px-3 py-2 font-medium">Threshold</th>
            <th scope="col" className="px-3 py-2 font-medium">Action</th>
            <th scope="col" className="px-3 py-2 font-medium">Priority</th>
            <th scope="col" className="px-3 py-2 font-medium">Recognizer</th>
            <th scope="col" className="px-3 py-2 font-medium">Description</th>
            {editable ? <th scope="col" className="px-3 py-2 font-medium">Remove</th> : null}
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => (
            <tr key={rule.entity_type} className="border-b border-edge/60 align-top">
              <td className="px-3 py-2">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  disabled={!editable}
                  aria-label={`${rule.entity_type} enabled`}
                  onChange={(event) =>
                    update(rule.entity_type, { enabled: event.target.checked })
                  }
                  className="h-3.5 w-3.5 accent-[#3fb950] disabled:opacity-50"
                />
              </td>
              <th scope="row" className="px-3 py-2 text-left font-mono font-normal text-ink">
                {rule.entity_type}
              </th>
              <td className="px-3 py-2">
                <input
                  type="number"
                  min={0}
                  max={1}
                  step={0.05}
                  value={rule.confidence_threshold}
                  disabled={!editable}
                  aria-label={`${rule.entity_type} confidence threshold`}
                  onChange={(event) =>
                    update(rule.entity_type, {
                      confidence_threshold: Number(event.target.value),
                    })
                  }
                  className="field w-20 px-2 py-1 font-mono text-[11px] disabled:opacity-60"
                />
              </td>
              <td className="px-3 py-2">
                <select
                  value={rule.action}
                  disabled={!editable}
                  aria-label={`${rule.entity_type} action`}
                  onChange={(event) =>
                    update(rule.entity_type, { action: event.target.value as EntityAction })
                  }
                  className={`field w-32 px-2 py-1 font-mono text-[11px] disabled:opacity-60 ${ACTION_TONE[rule.action]}`}
                >
                  {ENTITY_ACTIONS.map((action) => (
                    <option key={action} value={action}>
                      {action}
                    </option>
                  ))}
                </select>
              </td>
              <td className="px-3 py-2 font-mono text-[11px] text-muted">
                {rule.priority ?? "—"}
              </td>
              <td className="px-3 py-2 font-mono text-[11px] text-muted">
                {rule.recognizer ?? "—"}
              </td>
              <td className="max-w-[16rem] px-3 py-2 text-[11px] text-muted">
                {rule.description ?? "—"}
              </td>
              {editable ? (
                <td className="px-3 py-2">
                  <button
                    type="button"
                    className="btn-quiet"
                    onClick={() => onRemove?.(rule.entity_type)}
                  >
                    Remove
                  </button>
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
