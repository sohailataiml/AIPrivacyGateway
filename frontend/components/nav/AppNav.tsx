"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

/**
 * The application's two surfaces, grouped by what they are for.
 *
 * "Workspace" is where a user sends things through the gateway; "Security" is
 * where an operator configures what it does. Keeping them visibly separate is
 * the point -- they are different jobs, often different people, and the policy
 * surface is the one whose changes affect everyone else's traffic.
 *
 * The current section is marked with `aria-current`, not only with colour.
 */

const SECTIONS: ReadonlyArray<{ label: string; links: ReadonlyArray<[string, string]> }> = [
  { label: "Workspace", links: [["/chat", "Secure Chat"]] },
  { label: "Security", links: [["/policies", "Policies"]] },
];

export function AppNav() {
  const pathname = usePathname();

  return (
    <nav aria-label="Sections" className="flex flex-wrap items-center gap-x-5 gap-y-1">
      {SECTIONS.map((section) => (
        <div key={section.label} className="flex items-center gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-wide text-muted">
            {section.label}
          </span>
          {section.links.map(([href, label]) => {
            const active = pathname === href || pathname.startsWith(`${href}/`);
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={`rounded px-2 py-1 text-xs transition focus:outline-none focus:ring-2
                  focus:ring-accent ${
                    active
                      ? "bg-accent/15 text-accent"
                      : "text-muted hover:text-ink"
                  }`}
              >
                {label}
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
