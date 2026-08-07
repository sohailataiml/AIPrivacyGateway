import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure AI Gateway — Workspace",
  description:
    "Send prompts and documents through the privacy gateway and inspect what was protected.",
};

/**
 * Every page is rendered per request, so `proxy.ts` can stamp its CSP nonce.
 *
 * Next applies nonces during server-side rendering by reading the CSP header
 * off the *request*. A statically prerendered page is built when no request
 * exists, so there is no nonce to apply and its script tags ship without one --
 * and `'strict-dynamic'` then blocks every script on the page. The result is a
 * 200 with correct markup and no React: the shell renders, and nothing on it
 * responds.
 *
 * It sits in the layout rather than in `chat/page.tsx` because that page is a
 * Client Component, where route segment config does not apply. Declared here it
 * covers every route beneath it.
 *
 * The cost is real but small: these pages have no per-request server work worth
 * caching, and the data they show is fetched client-side through `/api` anyway.
 */
export const dynamic = "force-dynamic";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
