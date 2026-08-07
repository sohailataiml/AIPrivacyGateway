import { NextResponse, type NextRequest } from "next/server";

/**
 * Server-side proxy to the gateway, so the demo needs no API key.
 *
 * A reviewer opening the URL should be able to type a prompt, not hunt for a
 * credential. The obvious shortcut -- putting a key in a `NEXT_PUBLIC_*`
 * variable -- would bake it into the client bundle where anyone can read it,
 * which is the exact thing ADR-0019 and architecture.md 22.15 forbid. So the
 * key stays server-side: `GATEWAY_DEMO_API_KEY` is read here, in Node, and the
 * browser never sees it.
 *
 * Three things fall out of this that are worth knowing:
 *
 * * **A caller's own key still wins.** If the request arrives with an
 *   `Authorization` header, it is forwarded untouched. The paste-your-own-key
 *   path keeps working, and a reviewer with real credentials is not forced
 *   onto the demo one.
 * * **CORS stops mattering.** The browser now talks to this origin only, so
 *   `CORS_ALLOWED_ORIGINS` is no longer load-bearing for the workspace.
 * * **The demo key is as public as the URL.** Anyone who finds the site can
 *   spend it. `DEFAULT_PROVIDER=mock` means that costs nothing, and the
 *   gateway's own rate limiting is the control -- but do not point this at a
 *   paid provider without thinking about it.
 *
 * The body is streamed rather than buffered: document upload goes through here,
 * and reading a 25 MiB multipart body into memory to hand it straight on would
 * undo the streaming the upload path is built around.
 */

// `127.0.0.1`, not `localhost`. Node's fetch resolves `localhost` to `::1`
// first and does not fall back to IPv4, while docker-compose publishes the
// gateway on `127.0.0.1:8000` only. The pair fails with a bare "fetch failed",
// which this route reports as GATEWAY_UNREACHABLE -- and curl hides the problem
// completely, because curl *does* fall back. Every check that used curl passed
// while the browser could not reach the gateway at all.
const GATEWAY = process.env.GATEWAY_ORIGIN ?? "http://127.0.0.1:8000";
const DEMO_KEY = process.env.GATEWAY_DEMO_API_KEY;

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;

async function forward(request: NextRequest, path: string[]): Promise<Response> {
  const target = `${GATEWAY}/${path.join("/")}${request.nextUrl.search}`;

  const headers = new Headers();
  // Copy only what the upstream needs. Hop-by-hop headers and Next's own
  // internals are deliberately not passed along.
  //
  // `content-length` is pointedly NOT copied. The body is re-streamed, so the
  // inbound length no longer describes what goes out; fetch sends chunked and
  // the stale header either truncates the body or makes the request malformed.
  // Either way the gateway sees an unparseable payload and answers
  // INVALID_REQUEST -- a validation error that says nothing about the proxy
  // that caused it.
  for (const name of ["content-type", "accept"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }

  const caller = request.headers.get("authorization");
  if (caller) {
    headers.set("authorization", caller);
  } else if (DEMO_KEY) {
    headers.set("authorization", `Bearer ${DEMO_KEY}`);
  }

  const hasBody = request.method !== "GET" && request.method !== "DELETE";

  // The body is buffered, not streamed, and that is a deliberate retreat.
  //
  // This route originally forwarded `request.body` with `duplex: "half"` so a
  // large upload never had to land in memory. It does not work here: by the
  // time the handler runs, Next has already consumed the request, so the
  // stream is disturbed and undici rejects it with `expected non-null body
  // source`. That surfaces from `fetch` as the entirely generic "fetch
  // failed", so every POST returned GATEWAY_UNREACHABLE while GET -- having no
  // body to forward -- worked perfectly. The symptom looked like the gateway
  // being down, which it never was.
  //
  // The cost is real: a 25 MiB upload now occupies 25 MiB here on its way
  // through. It is bounded rather than unbounded -- the gateway enforces
  // MAX_DOCUMENT_BYTES and rejects anything larger -- but it is a genuine
  // regression against the streaming the upload path was built around, and it
  // is worth revisiting if Next exposes an undisturbed stream again.
  const body = hasBody ? await request.arrayBuffer() : null;

  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body,
      redirect: "manual",
      cache: "no-store",
    } as RequestInit);

    const proxied = new Headers();
    for (const name of ["content-type", "content-disposition"]) {
      const value = response.headers.get(name);
      if (value) proxied.set(name, value);
    }
    return new NextResponse(response.body, { status: response.status, headers: proxied });
  } catch (error) {
    // Logged server-side, returned as nothing. Swallowing it entirely made a
    // real outage indistinguishable from a bug in this file: "the gateway is
    // unavailable" was the only evidence available for a failure that was
    // actually a rejected request shape, and diagnosing it took three wrong
    // guesses. The cause goes to the server log, where an operator can read it
    // and a caller cannot.
    const cause = error instanceof Error ? (error.cause ?? error) : error;
    console.error("gateway_proxy_failed", {
      method: request.method,
      path: path.join("/"),
      error: error instanceof Error ? error.message : String(error),
      cause: cause instanceof Error ? cause.message : String(cause),
    });
    // The gateway's own error envelope, so the client's parser sees one shape
    // whatever went wrong. Nothing about the upstream is disclosed.
    return NextResponse.json(
      { error: { code: "GATEWAY_UNREACHABLE", message: "The gateway is unavailable." } },
      { status: 502 },
    );
  }
}

async function handler(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  const { path } = await context.params;
  return forward(request, path);
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const PATCH = handler;
export const DELETE = handler;

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export { METHODS };
