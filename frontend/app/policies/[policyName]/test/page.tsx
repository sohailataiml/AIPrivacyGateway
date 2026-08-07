"use client";

import Link from "next/link";
import { use, useState } from "react";

import { AppNav } from "@/components/nav/AppNav";
import { getApiKey } from "@/lib/credential";
import { GatewayError } from "@/lib/gateway";
import { testPolicy, type PolicyTestResult } from "@/lib/policies";

/**
 * The policy test playground.
 *
 * Type text, see what the chosen policy would do with it. The endpoint behind
 * this detects and resolves a policy and stops: it does not tokenize, write a
 * vault mapping, call a provider, or persist the input.
 *
 * Neither does this page. The text lives in component state for as long as the
 * tab is open and is never written to localStorage, sessionStorage, IndexedDB,
 * or a cookie -- the input here is the most sensitive thing in the application
 * by design, because an operator tests a policy with realistic data.
 *
 * The results carry offsets, never matched substrings, so the highlighted
 * preview is rendered by slicing the text the browser already has. Nothing
 * about a match comes back from the server.
 */

const SAMPLE =
  "Jordan Rivera called from 415-555-0142 about the invoice sent to " +
  "jordan.rivera@example.test. Card 4111 1111 1111 1111 on file.";

export default function PolicyTestPage({
  params,
}: {
  params: Promise<{ policyName: string }>;
}) {
  const { policyName } = use(params);
  const name = decodeURIComponent(policyName);

  const [text, setText] = useState(SAMPLE);
  const [result, setResult] = useState<PolicyTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      setResult(await testPolicy(getApiKey() ?? "", { text, policyName: name }));
    } catch (caught) {
      setResult(null);
      setError(
        caught instanceof GatewayError
          ? `${caught.message} (${caught.code})`
          : "The gateway could not be reached.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-surface">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-edge px-4 py-3 sm:px-5">
        <h1 className="text-sm font-semibold tracking-wide">Secure AI Gateway</h1>
        <AppNav />
      </header>

      <div className="mx-auto max-w-4xl p-4 sm:p-6">
        <Link
          href={`/policies/${encodeURIComponent(name)}`}
          className="text-[11px] text-muted hover:text-ink"
        >
          ← {name}
        </Link>
        <h2 className="mt-1 text-base font-semibold text-ink">Policy test playground</h2>
        <p className="mt-1 text-xs text-muted">
          Detects against the open draft if there is one, otherwise the active version. No
          provider is called and nothing is tokenized or stored.
        </p>

        <label htmlFor="test-text" className="mt-4 block text-xs font-medium text-muted">
          Synthetic input
        </label>
        <textarea
          id="test-text"
          className="field mt-1 min-h-[7rem] resize-y font-mono text-xs"
          value={text}
          maxLength={20000}
          onChange={(event) => setText(event.target.value)}
        />
        <p className="mt-1 text-[10px] text-muted">
          Use synthetic data. The text is sent to the detector and discarded; it is never
          written to browser storage.
        </p>

        <button
          type="button"
          className="btn mt-3"
          disabled={busy || text.trim().length === 0}
          onClick={() => void run()}
        >
          {busy ? "Running…" : "Run test"}
        </button>

        {error !== null ? (
          <p
            role="status"
            className="mt-4 rounded-md border border-danger/50 bg-danger/10 px-3 py-2 text-xs text-danger"
            data-testid="test-error"
          >
            {error}
          </p>
        ) : null}

        {result !== null ? (
          <section className="mt-5 space-y-4" aria-labelledby="result-heading">
            <h3 id="result-heading" className="text-xs font-semibold uppercase tracking-wide text-muted">
              Result — v{result.version} ({result.policy_status})
            </h3>

            {result.would_block ? (
              <p
                className="rounded-md border border-danger/50 bg-danger/10 px-3 py-2.5 text-xs font-semibold text-danger"
                data-testid="would-block"
              >
                <span aria-hidden>⦸</span> Provider would NOT be called
              </p>
            ) : (
              <p
                className="rounded-md border border-protect/50 bg-protect/10 px-3 py-2.5 text-xs text-protect"
                data-testid="would-send"
              >
                <span aria-hidden>✓</span> Provider would be called with protected values
              </p>
            )}

            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <div className="rounded-md border border-edge bg-panel px-2.5 py-2">
                <dt className="text-[10px] uppercase tracking-wide text-muted">Detected</dt>
                <dd className="mt-0.5 text-sm font-semibold text-ink">{result.detected}</dd>
              </div>
              {Object.entries(result.entity_types).map(([type, count]) => (
                <div key={type} className="rounded-md border border-edge bg-panel px-2.5 py-2">
                  <dt className="truncate font-mono text-[10px] text-muted">{type}</dt>
                  <dd className="mt-0.5 text-sm font-semibold text-ink">{count}</dd>
                </div>
              ))}
            </dl>

            <div className="overflow-x-auto">
              <table className="w-full min-w-[32rem] border-collapse text-xs" data-testid="span-table">
                <caption className="sr-only">Detected spans and intended actions</caption>
                <thead>
                  <tr className="border-b border-edge text-left text-[10px] uppercase tracking-wide text-muted">
                    <th scope="col" className="px-3 py-2 font-medium">Entity type</th>
                    <th scope="col" className="px-3 py-2 font-medium">Offsets</th>
                    <th scope="col" className="px-3 py-2 font-medium">Confidence</th>
                    <th scope="col" className="px-3 py-2 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {result.spans.map((span) => (
                    <tr
                      key={`${span.entity_type}-${span.start}-${span.end}`}
                      className="border-b border-edge/60"
                    >
                      <th scope="row" className="px-3 py-1.5 text-left font-mono font-normal text-ink">
                        {span.entity_type}
                      </th>
                      <td className="px-3 py-1.5 font-mono text-[11px] text-muted">
                        {span.start}–{span.end}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-[11px] text-muted">
                        {span.confidence.toFixed(2)}
                      </td>
                      <td
                        className={`px-3 py-1.5 font-mono text-[11px] ${
                          span.action === "block" ? "text-danger" : "text-protect"
                        }`}
                      >
                        {span.action}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {result.spans.length === 0 ? (
              <p className="text-xs text-muted">Nothing sensitive was detected.</p>
            ) : null}
          </section>
        ) : null}
      </div>
    </main>
  );
}
