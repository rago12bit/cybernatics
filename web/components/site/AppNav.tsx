"use client";

import Link from "next/link";
import * as RadixDropdown from "@radix-ui/react-dropdown-menu";
import { useEffect, useState } from "react";
import { getInbox } from "@/lib/api";
import "@/design-system/tokens.css";
import "@/design-system/primitives.css";

/* The app's own navigation, shown in the site header once you are signed in to /app: one header
   for the whole product instead of the site's bar with a second app bar under it. The pages people
   open every day are links; the rest sit under More, so the bar never wraps onto a second row. */

export type NavLink = { href: string; label: string };

export const APP_LINKS: NavLink[] = [
  { href: "/app", label: "Home" },
  { href: "/app/projects", label: "Projects" },
  { href: "/app/issues", label: "Issues" },
  { href: "/app/dashboards", label: "Dashboards" },
  { href: "/app/advisories", label: "Advisories" },
  { href: "/app/risk-acceptances", label: "Approvals" },
  { href: "/app/reports", label: "Reports" },
];

/** The rest of the app, grouped by what you came to do, each with a line saying what is there. */
export type MoreGroup = { id: string; label: string; links: (NavLink & { hint: string })[] };
export const MORE_GROUPS: MoreGroup[] = [
  { id: "work", label: "Work", links: [
    { href: "/app/scan", label: "Scan a codebase", hint: "A repository or an archive" },
    { href: "/app/calendar", label: "Calendar", hint: "SLA dates, engagements, expiring approvals" },
    { href: "/app/mentions", label: "Mentions", hint: "Notes that mention you" },
  ] },
  { id: "know", label: "Inventory", links: [
    { href: "/app/portfolios", label: "Business units", hint: "Projects grouped by who owns them" },
    { href: "/app/components", label: "Components", hint: "Every library across your projects" },
    { href: "/app/evidence", label: "Evidence", hint: "Packs for audits and compliance" },
    { href: "/app/costs", label: "Costs", hint: "What scanning costs" },
  ] },
  { id: "setup", label: "Set up", links: [
    { href: "/app/automation", label: "Automation", hint: "Rules that act on events" },
    { href: "/app/connectors", label: "Connectors", hint: "Pull from GitHub, GitLab, DefectDojo" },
    { href: "/app/settings", label: "Settings", hint: "People, sign-in, tokens, notifications" },
  ] },
];
export const MORE_LINKS: NavLink[] = MORE_GROUPS.flatMap((g) => g.links.map(({ href, label }) => ({ href, label })));

/** Home is current only on /app itself; every other link owns its whole subtree. */
export function isCurrent(path: string, href: string): boolean {
  return href === "/app" ? path === "/app" : path === href || path.startsWith(`${href}/`);
}

/** How many inbox items are unread (plan §49). Refreshes when the inbox page marks some read. */
export function useUnread(enabled: boolean): number {
  const [unread, setUnread] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    const load = () => getInbox(true).then((i) => setUnread(typeof i?.unread === "number" ? i.unread : 0), () => setUnread(0));
    load();
    window.addEventListener("bulwark:inbox", load);
    return () => window.removeEventListener("bulwark:inbox", load);
  }, [enabled]);
  return unread;
}

export function InboxLink({ path, unread, onClick }: { path: string; unread: number; onClick?: () => void }) {
  return (
    <Link href="/app/inbox" aria-current={isCurrent(path, "/app/inbox") ? "page" : undefined} aria-label={unread ? `Inbox, ${unread} unread` : "Inbox"} onClick={onClick}>
      Inbox{unread > 0 && <span className="nav-count" aria-hidden="true">{unread > 99 ? "99+" : unread}</span>}
    </Link>
  );
}

export function MoreMenu({ path }: { path: string }) {
  const current = MORE_LINKS.some((l) => isCurrent(path, l.href));
  return (
    <RadixDropdown.Root modal={false}>
      <RadixDropdown.Trigger className="nav-more" data-current={current || undefined}>
        More
        <svg className="nav-more-chevron" viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" focusable="false">
          <path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </RadixDropdown.Trigger>
      <RadixDropdown.Portal>
        <RadixDropdown.Content className="nav-more-menu" sideOffset={12} align="end" collisionPadding={16} loop>
          <div className="nav-more-groups">
            {MORE_GROUPS.map((g) => (
              <RadixDropdown.Group key={g.id} className={`nav-more-group g-${g.id}`} aria-labelledby={`more-${g.id}`}>
                <RadixDropdown.Label className="nav-more-label" id={`more-${g.id}`}>{g.label}</RadixDropdown.Label>
                {g.links.map((l) => (
                  <RadixDropdown.Item key={l.href} asChild className="nav-more-item">
                    <Link href={l.href} aria-current={isCurrent(path, l.href) ? "page" : undefined}>
                      <span className="t">{l.label}</span>
                      <span className="h">{l.hint}</span>
                    </Link>
                  </RadixDropdown.Item>
                ))}
              </RadixDropdown.Group>
            ))}
          </div>
          <p className="nav-more-foot" aria-hidden="true"><kbd>⌘</kbd><kbd>K</kbd> or <kbd>Ctrl</kbd><kbd>K</kbd> jumps to a project</p>
        </RadixDropdown.Content>
      </RadixDropdown.Portal>
    </RadixDropdown.Root>
  );
}
