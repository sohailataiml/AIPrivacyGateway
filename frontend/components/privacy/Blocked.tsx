"use client";

/**
 * A refusal, presented as the control working rather than the product failing.
 *
 * The distinction is real: `POLICY_VIOLATION` means a high-risk entity was
 * found and the request was never transmitted, which is the gateway doing its
 * job. Everything else is something being unavailable. They get different
 * wording and different emphasis, because telling an interviewer "error" when
 * the system just successfully protected them is the wrong story.
 *
 * The blocked value is not here, and cannot be: the error envelope carries a
 * code, a public message, and a request id. No entity type and no matched text
 * are returned for a block, so none are shown. Inventing "Entity type: US_SSN"
 * to fill the space would be a fabricated detail about the one thing that must
 * never be guessed at.
 */

export function BlockedNotice({ code, message }: { code: string; message: string }) {
  const isPolicyBlock = code === "POLICY_VIOLATION";

  return (
    <section
      className={`rounded-md border px-3 py-2.5 ${
        isPolicyBlock ? "border-warn/50 bg-warn/10" : "border-danger/50 bg-danger/10"
      }`}
      role="status"
      data-testid="blocked-notice"
    >
      <h3
        className={`flex items-center gap-1.5 text-xs font-semibold ${
          isPolicyBlock ? "text-warn" : "text-danger"
        }`}
      >
        <span aria-hidden>{isPolicyBlock ? "⦸" : "✕"}</span>
        {isPolicyBlock ? "Request blocked by privacy policy" : "Request refused"}
      </h3>

      {isPolicyBlock ? (
        <div className="mt-1.5 space-y-0.5 text-[11px] leading-relaxed text-ink">
          <p>A high-risk sensitive entity was detected.</p>
          <p>The request was not sent to the provider.</p>
        </div>
      ) : (
        // The gateway's own vetted public string, verbatim. The UI does not
        // invent an explanation for a refusal.
        <p className="mt-1.5 text-[11px] leading-relaxed text-ink">{message}</p>
      )}

      <p className="mt-1.5 font-mono text-[10px] text-muted">
        <span className="uppercase tracking-wide">Code</span> {code}
      </p>
    </section>
  );
}
