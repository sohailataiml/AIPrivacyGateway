import { NextResponse, type NextRequest } from "next/server";

/**
 * The Content Security Policy, issued per request with a fresh nonce.
 *
 * It lives here rather than in `next.config.mjs` because a static header cannot
 * carry a nonce, and without a nonce a strict `script-src` blocks Next's own
 * inline bootstrap scripts -- the ones carrying React's hydration payload. The
 * page then renders as dead HTML: it looks correct, and nothing on it works.
 *
 * That is not hypothetical. The first version of this application shipped
 * `script-src 'self'` from `next.config.mjs`, built cleanly, served 200, and
 * was completely non-interactive in a browser. `next build` does not evaluate
 * the CSP, and neither does an HTTP status check.
 *
 * `'strict-dynamic'` lets the nonce-carrying bootstrap load the rest of the
 * chunk graph without every chunk needing its own nonce. Browsers that honour
 * it ignore the `'self'` fallback beside it; older ones use `'self'`.
 *
 * Development additionally needs `'unsafe-eval'`, because Turbopack's hot
 * module replacement evaluates modules as strings. It is scoped to development
 * explicitly rather than left on -- the production bundle has no such need, and
 * an allowance that survives into production is the kind that stops being
 * noticed.
 *
 * **This file must be `proxy.ts`, exporting `proxy`.** Next 16 deprecated the
 * `middleware` convention and renamed it. The old name still *runs* -- it set
 * this very header -- but the nonce it puts on the request no longer reaches
 * the renderer, so every script tag shipped without one and `'strict-dynamic'`
 * blocked the lot. The page then served 200 with correct-looking markup and no
 * React at all: buttons did nothing, and the file picker opened (a native
 * `<label for>` behaviour needing no JS) while `onChange` never fired. Renaming
 * the file is the entire fix, and nothing in a build, a lint, or a status check
 * can see it.
 */

const isDevelopment = process.env.NODE_ENV === "development";

function policyFor(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDevelopment ? " 'unsafe-eval'" : ""}`,
    // Styles stay 'unsafe-inline': Next injects style tags, and inline CSS
    // cannot execute. The distinction from script is the whole point.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    // 'self' alone, because the browser now talks only to this origin: the
    // client calls `/api`, which the route handler forwards server-side. Any
    // direct call to a gateway origin is therefore a bug, and this turns it
    // into a visible console failure rather than a silent bypass of the proxy.
    `connect-src 'self'${isDevelopment ? " ws: wss:" : ""}`,
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

export function proxy(request: NextRequest): NextResponse {
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const policy = policyFor(nonce);

  // Next reads `x-nonce` off the request and stamps it onto the script tags it
  // renders, which is what makes them executable under the policy above.
  const forwarded = new Headers(request.headers);
  forwarded.set("x-nonce", nonce);
  forwarded.set("Content-Security-Policy", policy);

  const response = NextResponse.next({ request: { headers: forwarded } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export const config = {
  // `api` is excluded, and that is load-bearing rather than an optimisation.
  // Proxy runs on the Node.js runtime in Next 16 and re-issues the request with
  // mutated headers; doing that to `/api/[...path]` consumed the body stream the
  // route handler forwards upstream, so every POST failed with a bare "fetch
  // failed" while GET went through untouched. A route handler renders no HTML
  // and has no script tag to carry a nonce, so it gains nothing from the policy
  // anyway -- the responses it returns are JSON the browser never executes.
  //
  // Static assets and images are excluded for the ordinary reason: they do not
  // execute script and do not need a per-request nonce, and skipping them keeps
  // this off the hot path for every chunk.
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
