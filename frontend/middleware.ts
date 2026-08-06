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
 */

const isDevelopment = process.env.NODE_ENV === "development";
const gatewayOrigin = process.env.NEXT_PUBLIC_GATEWAY_ORIGIN ?? "http://localhost:8000";

function policyFor(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDevelopment ? " 'unsafe-eval'" : ""}`,
    // Styles stay 'unsafe-inline': Next injects style tags, and inline CSS
    // cannot execute. The distinction from script is the whole point.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    // The browser talks to this app and to the gateway. It has no business
    // reaching a provider, Redis, or PostgreSQL, and saying so here turns an
    // accidental direct call into a visible failure.
    `connect-src 'self' ${gatewayOrigin}${isDevelopment ? " ws: wss:" : ""}`,
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

export function middleware(request: NextRequest): NextResponse {
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
  // Static assets and images do not execute script and do not need a per-request
  // nonce; excluding them keeps the middleware off the hot path for every chunk.
  matcher: [
    {
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
