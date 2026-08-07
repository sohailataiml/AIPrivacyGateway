"use client";

import Link from "next/link";
import { use, useCallback, useEffect, useMemo, useState } from "react";

import { AppNav } from "@/components/nav/AppNav";
import { EntityTable } from "@/components/policy/EntityTable";
import { PublishDialog } from "@/components/policy/PublishDialog";
import { DiffView, VersionHistory } from "@/components/policy/VersionHistory";
import { getApiKey } from "@/lib/credential";
import { GatewayError } from "@/lib/gateway";
import {
  changeSummary,
  createDraft,
  discardDraft,
  documentFrom,
  getDetectorCatalog,
  getDiff,
  listVersions,
  publishDraft,
  riskyChanges,
  saveDraft,
  validateDraft,
  type DetectorCatalogEntry,
  type EntityRule,
  type PolicyDiff,
  type PolicyValidationResult,
  type PolicyVersion,
} from "@/lib/policies";

/**
 * Policy detail: metadata, the rule table, version history, and publishing.
 *
 * **Draft state lives in this component and nowhere else.** Not localStorage,
 * not sessionStorage, not a cookie -- ADR-0019 keeps browser storage free of
 * anything a caller typed, and a draft rule's description is free text an
 * operator might paste an identifier into. Reloading loses unsaved edits, which
 * is the honest consequence: what is saved is what the server has.
 *
 * The route parameter is the policy **name**. Every version row has its own id,
 * so no single id is stable across the history being managed.
 */

type Banner = { tone: "ok" | "bad"; text: string } | null;

export default function PolicyDetailPage({
  params,
}: {
  params: Promise<{ policyName: string }>;
}) {
  const { policyName } = use(params);
  const name = decodeURIComponent(policyName);

  const [versions, setVersions] = useState<PolicyVersion[] | null>(null);
  const [catalog, setCatalog] = useState<DetectorCatalogEntry[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [draftRules, setDraftRules] = useState<EntityRule[] | null>(null);
  const [diff, setDiff] = useState<PolicyDiff | null>(null);
  const [validation, setValidation] = useState<PolicyValidationResult | null>(null);
  const [banner, setBanner] = useState<Banner>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const draft = useMemo(
    () => versions?.find((version) => version.status === "draft") ?? null,
    [versions],
  );
  const active = useMemo(
    () => versions?.find((version) => version.is_active) ?? null,
    [versions],
  );
  const shown = useMemo(
    () => versions?.find((version) => version.version === selected) ?? active,
    [versions, selected, active],
  );

  const report = useCallback((caught: unknown) => {
    setBanner({
      tone: "bad",
      text:
        caught instanceof GatewayError
          ? `${caught.message} (${caught.code})`
          : "The gateway could not be reached.",
    });
  }, []);

  const load = useCallback(
    async (alive: () => boolean = () => true) => {
      // Nothing is set before the first await, so this is safe to call from an
      // effect; the guard stops a slow response writing to an unmounted page.
      try {
        const apiKey = getApiKey() ?? "";
        const [loaded, entries] = await Promise.all([
          listVersions(apiKey, name),
          getDetectorCatalog(apiKey).catch(() => [] as DetectorCatalogEntry[]),
        ]);
        if (!alive()) return;
        setVersions(loaded);
        setCatalog(entries);
        const openDraft = loaded.find((version) => version.status === "draft") ?? null;
        setDraftRules(openDraft === null ? null : openDraft.entity_rules.map((r) => ({ ...r })));
        setSelected(
          (openDraft ?? loaded.find((version) => version.is_active) ?? loaded.at(-1))?.version ??
            null,
        );
      } catch (caught) {
        if (!alive()) return;
        setVersions([]);
        report(caught);
      }
    },
    [name, report],
  );

  useEffect(() => {
    let mounted = true;
    // `load` sets state only after awaiting the network, so nothing is set
    // during commit -- which is what this rule guards against. The rule traces
    // the callback rather than the suspension point and cannot tell the
    // difference. Fetching here is unavoidable: the request needs the caller's
    // API key, which lives in memory on the client and is deliberately never
    // persisted (ADR-0019), so this cannot be a server component.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load(() => mounted);
    return () => {
      mounted = false;
    };
  }, [load]);

  async function guarded(work: () => Promise<void>): Promise<void> {
    setBusy(true);
    setBanner(null);
    try {
      await work();
    } catch (caught) {
      report(caught);
    } finally {
      setBusy(false);
    }
  }

  const summary = useMemo(
    () =>
      draft === null || draftRules === null ? [] : changeSummary(draft.entity_rules, draftRules),
    [draft, draftRules],
  );
  const risky = useMemo(
    () =>
      active === null || draftRules === null ? [] : riskyChanges(active.entity_rules, draftRules),
    [active, draftRules],
  );

  const addable = catalog.filter(
    (entry) => !(draftRules ?? []).some((rule) => rule.entity_type === entry.entity_type),
  );

  return (
    <main className="min-h-screen bg-surface">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-edge px-4 py-3 sm:px-5">
        <h1 className="text-sm font-semibold tracking-wide">Secure AI Gateway</h1>
        <AppNav />
      </header>

      <div className="mx-auto max-w-6xl p-4 sm:p-6">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <Link href="/policies" className="text-[11px] text-muted hover:text-ink">
              ← All policies
            </Link>
            <h2 className="mt-1 font-mono text-base font-semibold text-ink">{name}</h2>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Link href={`/policies/${encodeURIComponent(name)}/test`} className="btn-quiet">
              Test playground
            </Link>
            {draft === null ? (
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() =>
                  void guarded(async () => {
                    await createDraft(getApiKey() ?? "", name);
                    await load();
                    setBanner({ tone: "ok", text: "Draft created from the active version." });
                  })
                }
              >
                Create draft
              </button>
            ) : (
              <>
                <button
                  type="button"
                  className="btn-quiet"
                  disabled={busy}
                  onClick={() =>
                    void guarded(async () => {
                      await discardDraft(getApiKey() ?? "", name);
                      setValidation(null);
                      await load();
                      setBanner({ tone: "ok", text: "Draft discarded." });
                    })
                  }
                >
                  Discard draft
                </button>
                <button
                  type="button"
                  className="btn-quiet"
                  disabled={busy || draftRules === null}
                  onClick={() =>
                    void guarded(async () => {
                      const apiKey = getApiKey() ?? "";
                      await saveDraft(apiKey, name, documentFrom(draft, draftRules ?? []));
                      setValidation(await validateDraft(apiKey, name));
                      setBanner({ tone: "ok", text: "Draft saved and validated." });
                    })
                  }
                >
                  Save &amp; validate
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={busy}
                  onClick={() => setConfirming(true)}
                >
                  Publish…
                </button>
              </>
            )}
          </div>
        </div>

        {banner !== null ? (
          <p
            role="status"
            className={`mb-4 rounded-md border px-3 py-2 text-xs ${
              banner.tone === "ok"
                ? "border-protect/50 bg-protect/10 text-protect"
                : "border-danger/50 bg-danger/10 text-danger"
            }`}
            data-testid="policy-banner"
          >
            {banner.text}
          </p>
        ) : null}

        {validation !== null && validation.problems.length > 0 ? (
          <ul
            className="mb-4 rounded-md border border-danger/50 bg-danger/10 p-3 text-[11px]"
            data-testid="validation-problems"
          >
            {validation.problems.map((problem) => (
              <li key={`${problem.field}-${problem.code}`}>
                <span className="font-mono">{problem.field}</span> — {problem.message}
              </li>
            ))}
          </ul>
        ) : null}

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_18rem]">
          <div className="min-w-0 space-y-4">
            {shown !== null && shown !== undefined ? (
              <section className="panel p-4" aria-labelledby="metadata-heading">
                <h3 id="metadata-heading" className="text-xs font-semibold uppercase tracking-wide text-muted">
                  Version {shown.version}
                  {shown.status === "draft" ? " (draft)" : shown.is_active ? " (active)" : ""}
                </h3>
                <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-4">
                  <div>
                    <dt className="text-muted">Session TTL</dt>
                    <dd className="font-mono text-ink">{shown.session_ttl_seconds}s</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Max entities</dt>
                    <dd className="font-mono text-ink">{shown.max_entities}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Entity rules</dt>
                    <dd className="font-mono text-ink">{shown.entity_count}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Providers</dt>
                    <dd className="font-mono text-ink">
                      {Object.keys(shown.providers).join(", ") || "—"}
                    </dd>
                  </div>
                </dl>
              </section>
            ) : null}

            <section className="panel" aria-labelledby="rules-heading">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-edge px-4 py-2.5">
                <h3 id="rules-heading" className="text-xs font-semibold uppercase tracking-wide text-muted">
                  Entity rules
                </h3>
                {draft !== null && addable.length > 0 ? (
                  <label className="flex items-center gap-2 text-[11px] text-muted">
                    Add entity
                    <select
                      className="field w-48 px-2 py-1 text-[11px]"
                      value=""
                      aria-label="Add entity type"
                      onChange={(event) => {
                        const entry = addable.find((c) => c.entity_type === event.target.value);
                        if (entry === undefined || draftRules === null) return;
                        // Seeded from the catalog, so a new rule starts at the
                        // detector's own default rather than a number invented
                        // in the browser.
                        setDraftRules([
                          ...draftRules,
                          {
                            entity_type: entry.entity_type,
                            enabled: true,
                            confidence_threshold: entry.default_threshold,
                            action: "tokenize",
                            priority: null,
                            recognizer: entry.recognizer_type,
                            description: entry.description,
                          },
                        ]);
                      }}
                    >
                      <option value="">Choose…</option>
                      {addable.map((entry) => (
                        <option key={entry.entity_type} value={entry.entity_type}>
                          {entry.entity_type}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
              </div>
              <EntityTable
                rules={
                  draft !== null && draftRules !== null ? draftRules : (shown?.entity_rules ?? [])
                }
                onChange={draft !== null && draftRules !== null ? setDraftRules : null}
                onRemove={(entityType) =>
                  setDraftRules(
                    (draftRules ?? []).filter((rule) => rule.entity_type !== entityType),
                  )
                }
              />
            </section>

            {diff !== null ? (
              <section className="panel p-4">
                <DiffView diff={diff} />
              </section>
            ) : null}
          </div>

          <aside className="min-w-0 space-y-4">
            <section className="panel p-4" aria-labelledby="history-heading">
              <h3 id="history-heading" className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                Version history
              </h3>
              <VersionHistory
                versions={versions ?? []}
                selected={selected}
                onSelect={(version) => {
                  setSelected(version);
                  setDiff(null);
                }}
              />
              {(versions ?? []).length > 1 && selected !== null && selected > 1 ? (
                <button
                  type="button"
                  className="btn-quiet mt-3 w-full"
                  disabled={busy}
                  onClick={() =>
                    void guarded(async () => {
                      setDiff(
                        await getDiff(getApiKey() ?? "", name, selected - 1, selected),
                      );
                    })
                  }
                >
                  Compare with v{selected - 1}
                </button>
              ) : null}
            </section>
          </aside>
        </div>
      </div>

      <PublishDialog
        open={confirming}
        version={draft?.version ?? 0}
        summary={summary}
        risky={risky}
        validation={validation}
        busy={busy}
        onCancel={() => setConfirming(false)}
        onConfirm={() =>
          void guarded(async () => {
            const apiKey = getApiKey() ?? "";
            await saveDraft(apiKey, name, documentFrom(draft!, draftRules ?? []));
            const published = await publishDraft(apiKey, name);
            setConfirming(false);
            setValidation(null);
            await load();
            setBanner({ tone: "ok", text: `Version ${published.version} is now active.` });
          })
        }
      />
    </main>
  );
}
