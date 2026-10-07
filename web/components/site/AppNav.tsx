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

export const MORE_LINKS: NavLink[] = [
  { href: "/app/scan", label: "Scan a codebase" },
  { href: "/app/portfolios", label: "Business units" },
  { href: "/app/calendar", label: "Calendar" },
  { href: "/app/components", label: "Components" },
  { href: "/app/evidence", label: "Evidence" },
  { href: "/app/mentions", label: "Mentions" },
  { href: "/app/automation", label: "Automation" },
  { href: "/app/connectors", label: "Connectors" },
  { href: "/app/costs", label: "Costs" },
  { href: "/app/settings", label: "Settings" },
];

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
    <RadixDropdown.Root>
      <RadixDropdown.Trigger className="nav-more" data-current={current || undefined}>
        More <span aria-hidden="true">▾</span>
      </RadixDropdown.Trigger>
      <RadixDropdown.Portal>
        <RadixDropdown.Content className="ds-dropdown-content nav-more-menu" sideOffset={10} align="end">
          {MORE_LINKS.map((l) => (
            <RadixDropdown.Item key={l.href} asChild className="ds-dropdown-item">
              <Link href={l.href} aria-current={isCurrent(path, l.href) ? "page" : undefined}>{l.label}</Link>
            </RadixDropdown.Item>
          ))}
        </RadixDropdown.Content>
      </RadixDropdown.Portal>
    </RadixDropdown.Root>
  );
}
