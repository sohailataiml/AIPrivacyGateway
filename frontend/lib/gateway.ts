/**
 * The typed client for the gateway API. The only module that knows a URL.
 *
 * Everything the workspace shows comes back through here, and the shapes below
 * are deliberately narrow: they describe what the API *does* return, so a
 * component cannot render a field the backend never sends. `PrivacySummary` in
 * particular is counts and type names only -- there is no field on it that
 * could hold a detected value, which is the same guarantee the server-side
 * model carries.
 */

export interface PrivacySummary {
  detected: number;
  tokenized: number;
  redacted: number;
  pseudonymized: number;
  blocked: number;
  allowed: number;
  restored: number;
  unknown_tokens: number;
  /** Count per entity *type*. Names only -- never the values they stood for. */
  entity_types: Record<string, number>;
}

export interface ChatMessagePayload {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ProtectedEntitySummary {
  entity_type: string;
  count: number;
  action: string;
}

/**
 * A masked rendering of what the provider was sent.
 *
 * `text` arrives already masked. The browser never receives a full gateway
 * token and is never asked to hide one -- a client that had to mask would still
 * hold the token in memory, in the network tab, and in any error report the
 * page produced. Absent unless the deployment sets `PROTECTED_PREVIEW_ENABLED`.
 */
export interface ProtectedPreview {
  text: string | null;
  entity_summary: ProtectedEntitySummary[];
  outbound_scan: string;
  truncated: boolean;
}

export interface ChatResponse {
  request_id: string;
  session_id: string;
  provider: string;
  model: string;
  message: ChatMessagePayload;
  privacy: PrivacySummary;
  usage?: { input_tokens?: number; output_tokens?: number; total_tokens?: number } | null;
  protected_preview?: ProtectedPreview | null;
}

export interface DocumentResponse {
  id: string;
  filename: string;
  content_type: string;
  byte_size: number;
  status: string;
}

export interface ProcessDocumentResponse {
  request_id: string;
  session_id: string;
  document_id: string;
  provider: string;
  model: string;
  message: ChatMessagePayload;
  privacy: PrivacySummary;
  /** Keyed digest of the exact bytes sent upstream (ADR-0024). Never a payload. */
  outbound_attestation: string;
}

export interface GatewayErrorBody {
  error: { code: string; message: string; request_id?: string };
}

/**
 * A refusal from the gateway, carrying its stable machine-readable code.
 *
 * The code is what the UI branches on; the message is the server's own vetted
 * public string and is displayed verbatim. The frontend never invents an
 * explanation for a refusal -- inventing one is how a UI ends up telling a user
 * something the gateway deliberately declined to say.
 */
export class GatewayError extends Error {
  readonly code: string;
  readonly status: number;
  readonly requestId?: string;

  constructor(status: number, body: GatewayErrorBody | null, fallback: string) {
    // `body?.error.message` looks equivalent and is not: optional chaining stops
    // at `body`, so a response whose JSON parsed but has no `error` key throws a
    // TypeError here instead of producing an error object. That is not
    // hypothetical -- a bare 404 from the framework is `{"detail":"Not Found"}`,
    // and the thrown TypeError surfaced to the user as a *different* refusal
    // than the one that actually happened.
    const detail = body?.error;
    super(detail?.message ?? fallback);
    this.name = "GatewayError";
    this.status = status;
    this.code = detail?.code ?? `HTTP_${status}`;
    this.requestId = detail?.request_id;
  }
}

export const GATEWAY_ORIGIN = "/api";
/**
 * Same-origin, always. Requests go to this app's proxy route, which attaches a
 * server-side demo key and forwards to the gateway.
 *
 * Deliberately not a `NEXT_PUBLIC_*` gateway URL any more. Pointing the browser
 * straight at the API meant every visitor needed a credential, and the only way
 * to avoid that would have been shipping one in the client bundle. Going
 * through the proxy also makes CORS irrelevant for the workspace.
 */

async function refuse(response: Response): Promise<never> {
  let body: GatewayErrorBody | null = null;
  try {
    body = (await response.json()) as GatewayErrorBody;
  } catch {
    // A non-JSON body means something upstream of the application answered.
    // There is nothing safe to quote from it, so it is not quoted.
    body = null;
  }
  throw new GatewayError(response.status, body, `Request failed (${response.status}).`);
}

function authHeaders(apiKey: string): HeadersInit {
  // Empty when the caller has no key of their own -- the proxy then fills in
  // the demo credential server-side. Sending `Bearer ` with nothing after it
  // would be a malformed header rather than an absent one.
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
}

/**
 * The one place a policy request is made.
 *
 * Exported so `lib/policies.ts` can build on it instead of reaching for
 * `fetch` again. Every call in this application goes through this function or
 * one of the typed wrappers below it, which is what keeps the refusal shape,
 * the auth header, and the `/api` origin in a single place rather than
 * scattered across components that each get one detail slightly wrong.
 */
export async function request<T>(
  path: string,
  init: { method?: string; apiKey: string; body?: unknown; signal?: AbortSignal } = {
    apiKey: "",
  },
): Promise<T> {
  const hasBody = init.body !== undefined;
  const response = await fetch(`${GATEWAY_ORIGIN}${path}`, {
    method: init.method ?? "GET",
    headers: {
      ...authHeaders(init.apiKey),
      ...(hasBody ? { "Content-Type": "application/json" } : {}),
    },
    ...(hasBody ? { body: JSON.stringify(init.body) } : {}),
    signal: init.signal,
  });
  if (!response.ok) return refuse(response);
  // 204 has no body to parse, and calling `.json()` on one throws.
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export interface ChatRequestInput {
  apiKey: string;
  provider: string;
  model: string;
  content: string;
  sessionId?: string;
  signal?: AbortSignal;
}

export async function sendChat(input: ChatRequestInput): Promise<ChatResponse> {
  const response = await fetch(`${GATEWAY_ORIGIN}/v1/chat`, {
    method: "POST",
    headers: { ...authHeaders(input.apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({
      provider: input.provider,
      model: input.model,
      messages: [{ role: "user", content: input.content }],
      ...(input.sessionId ? { session_id: input.sessionId } : {}),
    }),
    signal: input.signal,
  });
  if (!response.ok) return refuse(response);
  return (await response.json()) as ChatResponse;
}

export interface UploadInput {
  apiKey: string;
  file: File;
  signal?: AbortSignal;
}

export async function uploadDocument(input: UploadInput): Promise<DocumentResponse> {
  const form = new FormData();
  form.append("file", input.file);
  const response = await fetch(`${GATEWAY_ORIGIN}/v1/documents`, {
    method: "POST",
    // No Content-Type: the browser sets the multipart boundary, and setting it
    // by hand is the classic way to produce an unparseable body.
    headers: authHeaders(input.apiKey),
    body: form,
    signal: input.signal,
  });
  if (!response.ok) return refuse(response);
  return (await response.json()) as DocumentResponse;
}

export interface ProcessInput {
  apiKey: string;
  documentId: string;
  provider: string;
  model: string;
  instruction: string;
  sessionId?: string;
  signal?: AbortSignal;
}

export async function processDocument(input: ProcessInput): Promise<ProcessDocumentResponse> {
  const response = await fetch(
    `${GATEWAY_ORIGIN}/v1/documents/${encodeURIComponent(input.documentId)}/process`,
    {
      method: "POST",
      headers: { ...authHeaders(input.apiKey), "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: input.provider,
        model: input.model,
        instruction: input.instruction,
        ...(input.sessionId ? { session_id: input.sessionId } : {}),
      }),
      signal: input.signal,
    },
  );
  if (!response.ok) return refuse(response);
  return (await response.json()) as ProcessDocumentResponse;
}
