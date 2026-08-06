"use client";

import { useCallback, useState, useSyncExternalStore } from "react";

import { Composer } from "@/components/chat/Composer";
import { Conversation, type Turn } from "@/components/chat/Conversation";
import { Inspector } from "@/components/privacy/Inspector";
import { apiKeyLabel, clearApiKey, getApiKey, hasApiKey, setApiKey, subscribe } from "@/lib/credential";
import {
  GatewayError,
  processDocument,
  sendChat,
  uploadDocument,
  type PrivacySummary,
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
  policyVersion: number | null;
  attestation: string | null;
  elapsedMs: number | null;
  refusalCode: string | null;
}

const EMPTY: Snapshot = {
  summary: null,
  requestId: null,
  policyVersion: null,
  attestation: null,
  elapsedMs: null,
  refusalCode: null,
};

let turnCounter = 0;
const nextId = () => `turn-${++turnCounter}`;

export default function ChatWorkspace() {
  const authenticated = useSyncExternalStore(subscribe, hasApiKey, () => false);
  const keyLabel = useSyncExternalStore(subscribe, apiKeyLabel, () => null);

  const [turns, setTurns] = useState<readonly Turn[]>([]);
  const [attachment, setAttachment] = useState<File | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [stage, setStage] = useState<InspectorStage>("idle");
  const [snapshot, setSnapshot] = useState<Snapshot>(EMPTY);

  const append = useCallback((turn: Omit<Turn, "id">) => {
    setTurns((current) => [...current, { ...turn, id: nextId() }]);
  }, []);

  const send = useCallback(
    async (text: string) => {
      const apiKey = getApiKey();
      if (!apiKey) return;

      const file = attachment;
      append({ author: "you", text, documentName: file?.name });
      setSnapshot(EMPTY);
      const started = performance.now();

      try {
        if (file) {
          setStage("uploading");
          const stored = await uploadDocument({ apiKey, file });
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
          append({ author: "gateway", text: answer.message.content });
          setSnapshot({
            summary: answer.privacy,
            requestId: answer.request_id,
            policyVersion: null,
            attestation: answer.outbound_attestation,
            elapsedMs: Math.round(performance.now() - started),
            refusalCode: null,
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
          append({ author: "gateway", text: answer.message.content });
          setSnapshot({
            summary: answer.privacy,
            requestId: answer.request_id,
            policyVersion: null,
            attestation: null,
            elapsedMs: Math.round(performance.now() - started),
            refusalCode: null,
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
        setSnapshot({
          ...EMPTY,
          requestId: refusal.requestId,
          refusalCode: refusal.code,
          elapsedMs: Math.round(performance.now() - started),
        });
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

      {authenticated ? (
        <div className="grid min-h-0 grid-cols-1 gap-4 p-4 lg:grid-cols-[1fr_22rem]">
          <section className="panel flex min-h-0 flex-col">
            <Conversation turns={turns} />
            <Composer
              disabled={busy}
              attachment={attachment}
              onAttach={setAttachment}
              onSend={(text) => void send(text)}
            />
          </section>
          <Inspector
            stage={stage}
            summary={snapshot.summary}
            requestId={snapshot.requestId}
            sessionId={sessionId}
            policyVersion={snapshot.policyVersion}
            attestation={snapshot.attestation}
            elapsedMs={snapshot.elapsedMs}
            refusalCode={snapshot.refusalCode}
          />
        </div>
      ) : (
        <ApiKeyGate />
      )}
    </main>
  );
}

function Header({
  keyLabel,
  sessionId,
  onClearSession,
  onSignOut,
}: {
  keyLabel: string | null;
  sessionId: string | null;
  onClearSession: () => void;
  onSignOut: () => void;
}) {
  return (
    <header className="flex items-center justify-between border-b border-edge px-5 py-3">
      <div className="flex items-baseline gap-3">
        <h1 className="text-sm font-semibold tracking-wide">Secure AI Gateway</h1>
        <span className="font-mono text-[11px] text-muted">
          {DEFAULT_PROVIDER} · {DEFAULT_MODEL}
        </span>
      </div>
      {keyLabel ? (
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] text-muted">{keyLabel}</span>
          <button type="button" className="btn-quiet" onClick={onClearSession} disabled={!sessionId}>
            Clear session
          </button>
          <button type="button" className="btn-quiet" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      ) : null}
    </header>
  );
}

function ApiKeyGate() {
  const [value, setValue] = useState("");
  return (
    <div className="flex items-center justify-center p-8">
      <form
        className="panel w-full max-w-md space-y-4 p-6"
        onSubmit={(event) => {
          event.preventDefault();
          setApiKey(value);
          setValue("");
        }}
      >
        <div>
          <h2 className="text-sm font-semibold">API key</h2>
          <p className="mt-1 text-xs text-muted">
            Held in memory for this tab only and lost on reload. It is never written to
            local storage, session storage, or a cookie (ADR-0019).
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
