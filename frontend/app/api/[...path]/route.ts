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

const GATEWAY = process.env.GATEWAY_ORIGIN ?? "http://localhost:8000";
const DEMO_KEY = process.env.GATEWAY_DEMO_API_KEY;

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;

async function forward(request: NextRequest, path: string[]): Promise<Response> {
  const target = `${GATEWAY}/${path.join("/")}${request.nextUrl.search}`;

  const headers = new Headers();
  // Copy only what the upstream needs. Hop-by-hop headers and Next's own
  // internals are deliberately not passed along.
  for (const name of ["content-type", "accept", "content-length"]) {
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

  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      // Required by undici whenever a stream is used as the body.
      ...(hasBody ? { duplex: "half" } : {}),
      redirect: "manual",
      cache: "no-store",
    } as RequestInit);

    const proxied = new Headers();
    for (const name of ["content-type", "content-disposition"]) {
      const value = response.headers.get(name);
      if (value) proxied.set(name, value);
    }
    return new NextResponse(response.body, { status: response.status, headers: proxied });
  } catch {
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
