"use client";

import { useCallback, useState, useSyncExternalStore } from "react";

import { AppNav } from "@/components/nav/AppNav";
import { Composer } from "@/components/chat/Composer";
import { Conversation, type Turn } from "@/components/chat/Conversation";
import type { DocumentStatus } from "@/components/documents/DocumentCard";
import { HowItWorks } from "@/components/HowItWorks";
import { Inspector } from "@/components/privacy/Inspector";
import { apiKeyLabel, clearApiKey, getApiKey, hasApiKey, setApiKey, subscribe } from "@/lib/credential";
import {
  GatewayError,
  processDocument,
  sendChat,
  uploadDocument,
  type PrivacySummary,
  type ProtectedPreview,
} from "@/lib/gateway";
import type { InspectorStage } from "@/lib/inspector";

/**
 * The secure chat workspace (architecture.md section 22.6).
 *
 * The session id is the one piece of cross-request state this page keeps, and
 * it matters more than it looks. Vault mappings are session-scoped, so reusing
 * the id is what lets a token minted for an uploaded document resolve in a
 * later prompt about it — one identifier for one person across the whole
 * conversation. Clearing the session is therefore a real privacy action, not a
 * UI reset: the mappings behind those tokens stop being reachable.
 */

const DEFAULT_PROVIDER = "mock";
const DEFAULT_MODEL = "general-chat";

interface Snapshot {
  summary: PrivacySummary | null;
  requestId: string | null;
  /**
   * No v1 response carries a policy version, so this is always null today.
   * The field is kept because the inspector reports the absence rather than
   * hiding it, and inventing a number would be the one thing item 14 of the
   * brief forbids.
   */
  policyVersion: number | null;
  attestation: string | null;
  elapsedMs: number | null;
  refusalCode: string | null;
  refusalMessage: string | null;
  provider: string | null;
  document: DocumentStatus | null;
  preview: ProtectedPreview | null;
}

const EMPTY: Snapshot = {
  summary: null,
  requestId: null,
  policyVersion: null,
  attestation: null,
  elapsedMs: null,
  refusalCode: null,
  refusalMessage: null,
  provider: null,
  document: null,
  preview: null,
};

let turnCounter = 0;
const nextId = () => `turn-${++turnCounter}`;

export default function ChatWorkspace() {
  const keyLabel = useSyncExternalStore(subscribe, apiKeyLabel, () => null);

  const [turns, setTurns] = useState<readonly Turn[]>([]);
  const [attachment, setAttachment] = useState<File | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [stage, setStage] = useState<InspectorStage>("idle");
  const [snapshot, setSnapshot] = useState<Snapshot>(EMPTY);
  const [showKeyForm, setShowKeyForm] = useState(false);
  const [showHowItWorks, setShowHowItWorks] = useState(false);
  const usingOwnKey = useSyncExternalStore(subscribe, hasApiKey, () => false);

  const append = useCallback((turn: Omit<Turn, "id">) => {
    setTurns((current) => [...current, { ...turn, id: nextId() }]);
  }, []);

  const send = useCallback(
    async (text: string) => {
      // Empty string is valid: the proxy attaches the demo key server-side when
      // the caller has none. Only a caller who pasted their own key sends one.
      const apiKey = getApiKey() ?? "";

      const file = attachment;
      append({ author: "you", text, documentName: file?.name });
      setSnapshot(EMPTY);
      const started = performance.now();

      try {
        if (file) {
          setStage("uploading");
          const stored = await uploadDocument({ apiKey, file });
          // Shown as soon as the upload returns, so the document card reflects
          // real status during the longer processing call rather than after it.
          const uploaded: DocumentStatus = {
            name: stored.filename,
            status: stored.status,
            byteSize: stored.byte_size,
            detected: null,
          };
          setSnapshot((current) => ({ ...current, document: uploaded }));
          setStage("in_flight");
          const answer = await processDocument({
            apiKey,
            documentId: stored.id,
            provider: DEFAULT_PROVIDER,
            model: DEFAULT_MODEL,
            instruction: text,
            ...(sessionId ? { sessionId } : {}),
          });
          setSessionId(answer.session_id);
          setAttachment(null);
          append({
            author: "gateway",
            text: answer.message.content,
            provider: answer.provider,
            restored: answer.privacy.restored,
          });
          setSnapshot({
            summary: answer.privacy,
            requestId: answer.request_id,
            policyVersion: null,
            attestation: answer.outbound_attestation,
            elapsedMs: Math.round(performance.now() - started),
            refusalCode: null,
            refusalMessage: null,
            provider: answer.provider,
            document: { ...uploaded, detected: answer.privacy.detected },
            // No preview on the document path: it would render extracted
            // document body text, which this panel has never shown and which
            // ADR-0030 deliberately keeps out of storage. The counts and the
            // attestation still describe what happened.
            preview: null,
          });
        } else {
          setStage("in_flight");
          const answer = await sendChat({
            apiKey,
            provider: DEFAULT_PROVIDER,
            model: DEFAULT_MODEL,
            content: text,
            ...(sessionId ? { sessionId } : {}),
          });
          setSessionId(answer.session_id);
          append({
            author: "gateway",
            text: answer.message.content,
            provider: answer.provider,
            restored: answer.privacy.restored,
          });
          setSnapshot({
            summary: answer.privacy,
            requestId: answer.request_id,
            policyVersion: null,
            attestation: null,
            elapsedMs: Math.round(performance.now() - started),
            refusalCode: null,
            refusalMessage: null,
            provider: answer.provider,
            document: null,
            preview: answer.protected_preview ?? null,
          });
        }
        setStage("completed");
      } catch (error) {
        // The gateway's own public message, verbatim. The UI does not invent an
        // explanation for a refusal -- that is how a screen ends up saying
        // something the gateway deliberately declined to say.
        const refusal =
          error instanceof GatewayError
            ? { code: error.code, message: error.message, requestId: error.requestId ?? null }
            : { code: "NETWORK", message: "The gateway could not be reached.", requestId: null };
        append({ author: "system", text: refusal.message });
        setSnapshot((current) => ({
          ...EMPTY,
          // A document that uploaded before the refusal really did upload, so
          // its card survives; anything derived from the failed call does not.
          document: current.document === null ? null : { ...current.document, detected: null },
          requestId: refusal.requestId,
          refusalCode: refusal.code,
          refusalMessage: refusal.message,
          elapsedMs: Math.round(performance.now() - started),
        }));
        setStage("refused");
      }
    },
    [append, attachment, sessionId],
  );

  const busy = stage === "uploading" || stage === "in_flight";

  return (
    <main className="grid h-screen grid-rows-[auto_1fr] bg-surface">
      <Header
        keyLabel={keyLabel}
        usingOwnKey={usingOwnKey}
        onToggleKeyForm={() => setShowKeyForm((open) => !open)}
        onHowItWorks={() => setShowHowItWorks(true)}
        sessionId={sessionId}
        onClearSession={() => {
          // A new session is a new vault namespace: tokens from the old one
          // stop resolving. The conversation is cleared with it because leaving
          // it on screen would imply those turns are still restorable.
          setSessionId(null);
          setTurns([]);
          setSnapshot(EMPTY);
          setStage("idle");
        }}
        onSignOut={clearApiKey}
      />

      {showKeyForm ? <ApiKeyGate onDone={() => setShowKeyForm(false)} /> : null}

      {/* Single column until `lg`, where the inspector moves alongside. Both
          children get `min-h-0` so each scrolls internally instead of pushing
          the page into a horizontal or full-document scroll. */}
      <div className="grid min-h-0 grid-cols-1 gap-4 overflow-y-auto p-4 lg:grid-cols-[minmax(0,1fr)_23rem] lg:overflow-hidden">
        <section className="panel flex min-h-[24rem] min-w-0 flex-col lg:min-h-0">
          <Conversation turns={turns} />
          <Composer
            disabled={busy}
            attachment={attachment}
            onAttach={setAttachment}
            onSend={(text) => void send(text)}
          />
        </section>
        <div className="min-h-0 min-w-0">
          <Inspector
            stage={stage}
            summary={snapshot.summary}
            requestId={snapshot.requestId}
            sessionId={sessionId}
            policyVersion={snapshot.policyVersion}
            attestation={snapshot.attestation}
            elapsedMs={snapshot.elapsedMs}
            refusalCode={snapshot.refusalCode}
            refusalMessage={snapshot.refusalMessage}
            provider={snapshot.provider}
            document={snapshot.document}
            preview={snapshot.preview}
          />
        </div>
      </div>

      <HowItWorks open={showHowItWorks} onClose={() => setShowHowItWorks(false)} />
    </main>
  );
}

function Header({
  keyLabel,
  usingOwnKey,
  onToggleKeyForm,
  onHowItWorks,
  sessionId,
  onClearSession,
  onSignOut,
}: {
  keyLabel: string | null;
  usingOwnKey: boolean;
  onToggleKeyForm: () => void;
  onHowItWorks: () => void;
  sessionId: string | null;
  onClearSession: () => void;
  onSignOut: () => void;
}) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-edge px-4 py-3 sm:px-5">
      <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h1 className="text-sm font-semibold tracking-wide">Secure AI Gateway</h1>
        <AppNav />
        <span className="hidden font-mono text-[11px] text-muted lg:inline">
          {DEFAULT_PROVIDER} · {DEFAULT_MODEL}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="hidden font-mono text-[11px] text-muted sm:inline">
          {usingOwnKey ? keyLabel : "demo credential"}
        </span>
        <button type="button" className="btn-quiet" onClick={onHowItWorks}>
          How it works
        </button>
        <button type="button" className="btn-quiet" onClick={onClearSession} disabled={!sessionId}>
          Clear session
        </button>
        {usingOwnKey ? (
          <button type="button" className="btn-quiet" onClick={onSignOut}>
            Use demo key
          </button>
        ) : (
          <button type="button" className="btn-quiet" onClick={onToggleKeyForm}>
            Use my key
          </button>
        )}
      </div>
    </header>
  );
}

function ApiKeyGate({ onDone }: { onDone: () => void }) {
  const [value, setValue] = useState("");
  return (
    <div className="flex items-start justify-center p-8">
      <form
        className="panel w-full max-w-md space-y-4 p-6"
        onSubmit={(event) => {
          event.preventDefault();
          setApiKey(value);
          setValue("");
          onDone();
        }}
      >
        <div>
          <h2 className="text-sm font-semibold">Use your own API key</h2>
          <p className="mt-1 text-xs text-muted">
            Optional. Without one, requests use a demo credential attached
            server-side, which the browser never sees. Either way no key is
            written to local storage, session storage, or a cookie (ADR-0019) --
            one you paste here is held in memory for this tab and lost on reload.
          </p>
        </div>
        <label htmlFor="api-key" className="sr-only">
          API key
        </label>
        <input
          id="api-key"
          type="password"
          className="field font-mono"
          placeholder="sgw_live_…"
          autoComplete="off"
          value={value}
          onChange={(event) => setValue(event.target.value)}
        />
        <button type="submit" className="btn w-full" disabled={value.trim().length === 0}>
          Continue
        </button>
      </form>
    </div>
  );
}
