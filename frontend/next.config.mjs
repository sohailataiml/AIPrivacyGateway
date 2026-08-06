/**
 * Next.js configuration, and the one place the browser-side security headers
 * from architecture.md section 22.15 are set.
 *
 * The CSP is deliberately strict and deliberately *not* `unsafe-inline` for
 * scripts. This application renders model output, and model output is the one
 * string on the page that an attacker upstream has influence over -- a policy
 * that permits inline script is a policy that stops mattering exactly when it
 * would have helped.
 *
 * `connect-src` is limited to self and the gateway origin: the browser has no
 * business reaching a provider, Redis, or PostgreSQL, and stating that here
 * makes an accidental direct call fail loudly rather than work.
 */

/** @type {import('next').NextConfig} */
const gatewayOrigin = process.env.NEXT_PUBLIC_GATEWAY_ORIGIN ?? "http://localhost:8000";

const contentSecurityPolicy = [
  "default-src 'self'",
  // Next injects a small runtime; 'unsafe-inline' for *style* only, which
  // cannot execute. Scripts get no such allowance.
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  `connect-src 'self' ${gatewayOrigin}`,
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: contentSecurityPolicy },
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
