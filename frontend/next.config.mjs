/**
 * Next.js configuration: the security headers that do *not* vary per request.
 *
 * The Content Security Policy is deliberately **not** here. It needs a fresh
 * nonce on every response so Next's inline bootstrap scripts can execute under
 * a strict `script-src`, and a static header cannot carry one. It lives in
 * `middleware.ts`, which explains what happens when it does not.
 *
 * Two CSP headers would be worse than one: browsers enforce the intersection,
 * so a stale strict copy here would silently override the nonce policy and
 * break hydration again.
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
          },
        ],
      },
    ];
  },
};

export default nextConfig;
