import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Secure AI Gateway — Workspace",
  description:
    "Send prompts and documents through the privacy gateway and inspect what was protected.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
