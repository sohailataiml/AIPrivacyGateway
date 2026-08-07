"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { AppNav } from "@/components/nav/AppNav";
import { getApiKey } from "@/lib/credential";
import { GatewayError } from "@/lib/gateway";
import { listPolicies, type PolicySummary } from "@/lib/policies";

/**
 * The policy list.
 *
 * Everything on screen is read from `/v1/policies`. There is no seeded row, no
 * placeholder policy, and no "default" invented client-side: an empty list
 * means the tenant has no policy, which is a real state worth showing rather
 * than papering over.
 */

function formatTime(value: string | null): string {
  return value === null ? "Never" : value.replace("T", " ").replace(/\.\d+/, "").replace("Z", " UTC");
}

export default function PolicyListPage() {
  const [policies, setPolicies] = useState<PolicySummary[] | null>(null);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);

  const load = useCallback(async (alive: () => boolean) => {
    // Nothing is set before the first await: a synchronous setState inside an
    // effect re-renders during commit, which React 19 flags. The guard is not
    // ceremony either -- navigating away mid-request would otherwise set state
    // on an unmounted component.
    try {
      const loaded = await listPolicies(getApiKey() ?? "");
      if (!alive()) return;
      setPolicies(loaded);
      setError(null);
    } catch (caught) {
      if (!alive()) return;
      setPolicies([]);
      setError(
        caught instanceof GatewayError
          ? { code: caught.code, message: caught.message }
          : { code: "NETWORK", message: "The gateway could not be reached." },
      );
    }
  }, []);

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

  return (
    <main className="min-h-screen bg-surface">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-edge px-4 py-3 sm:px-5">
        <h1 className="text-sm font-semibold tracking-wide">Secure AI Gateway</h1>
        <AppNav />
      </header>

      <div className="mx-auto max-w-5xl p-4 sm:p-6">
        <div className="mb-4">
          <h2 className="text-base font-semibold text-ink">Policies</h2>
          <p className="mt-1 text-xs text-muted">
            What the gateway detects, and what it does about it. Published versions are
            immutable; edits happen on a draft.
          </p>
        </div>

        {error !== null ? (
          <div
            role="status"
            className="rounded-md border border-danger/50 bg-danger/10 px-3 py-2.5"
            data-testid="policy-list-error"
          >
            <p className="text-xs font-semibold text-danger">{error.message}</p>
            <p className="mt-1 font-mono text-[10px] text-muted">{error.code}</p>
          </div>
        ) : null}

        {policies === null ? (
          <p className="text-xs text-muted">Loading…</p>
        ) : policies.length === 0 && error === null ? (
          <p className="text-xs text-muted">This tenant has no policies.</p>
        ) : (
          <ul className="space-y-2" data-testid="policy-list">
            {policies.map((policy) => (
              <li key={policy.policy_name}>
                <Link
                  href={`/policies/${encodeURIComponent(policy.policy_name)}`}
                  className="panel block p-4 transition hover:border-accent focus:outline-none
                             focus:ring-2 focus:ring-accent"
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="font-mono text-sm text-ink">{policy.policy_name}</span>
                    <span className="flex items-center gap-2">
                      {policy.draft_version !== null ? (
                        <span className="rounded border border-warn/40 bg-warn/10 px-1.5 py-0.5 text-[10px] text-warn">
                          Draft v{policy.draft_version}
                        </span>
                      ) : null}
                      <span className="rounded border border-protect/40 bg-protect/10 px-1.5 py-0.5 text-[10px] text-protect">
                        Active v{policy.active_version ?? "—"}
                      </span>
                    </span>
                  </div>
                  <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-4">
                    <div>
                      <dt className="text-muted">Entities</dt>
                      <dd className="font-mono text-ink">{policy.entity_count}</dd>
                    </div>
                    <div>
                      <dt className="text-muted">Enabled</dt>
                      <dd className="font-mono text-ink">{policy.enabled_entity_count}</dd>
                    </div>
                    <div>
                      <dt className="text-muted">Versions</dt>
                      <dd className="font-mono text-ink">{policy.version_count}</dd>
                    </div>
                    <div>
                      <dt className="text-muted">Last published</dt>
                      <dd className="text-ink">{formatTime(policy.last_published_at)}</dd>
                    </div>
                  </dl>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}
