"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { getInbox, listAssets } from "@/lib/api";
import type { AssetSummary } from "@/lib/types";
import { DropdownMenuChildren } from "@/design-system/primitives/DropdownMenu";
import { Dialog as DsDialog } from "@/design-system/primitives/Dialog";
import { Button } from "@/design-system/primitives/Button";
import { TooltipProvider } from "@/design-system/primitives/Tooltip";
import { ModeProvider } from "@/design-system/mode";
import * as RadixDropdown from "@radix-ui/react-dropdown-menu";
import "@/design-system/fonts.css";
import "@/design-system/tokens.css";
import "./shell.css";

export type Crumb = { label: string; href?: string };

/**
 * The nav shell for the new (plan §29-built) screens: an organization/project switcher, breadcrumbs,
 * a command palette (Cmd/Ctrl+K), and shortcut help (?) — plan §27, §30.1, Week 33. This wraps only
 * the new project-overview routes; nothing under the old /app screens uses it (Week 32's "additive,
 * migrate screen by screen" decision — see docs/v2-week33-verification.md).
 */
export function AppShell({ crumbs, children }: { crumbs: Crumb[]; children: ReactNode }) {
  const router = useRouter();
  const [assets, setAssets] = useState<AssetSummary[] | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  useEffect(() => {
    listAssets().then(setAssets, () => setAssets([]));
  }, []);

  // Global shortcuts (§30.1): Cmd/Ctrl+K opens the palette, ? opens the shortcut help. Both are
  // suppressed while the person is typing into a field, so "?" still types a literal question mark
  // in a search box instead of hijacking it.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      } else if (e.key === "?" && !typing) {
        e.preventDefault();
        setShortcutsOpen(true);
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  return (
    <ModeProvider>
    <TooltipProvider>
      <div className="ds-shell">
        <header className="ds-shell-top">
          <Link href="/app" className="ds-shell-brand">Bulwark</Link>
          <nav aria-label="Breadcrumb" className="ds-shell-crumbs">
            {crumbs.map((c, i) => (
              <span key={i}>
                {i > 0 && <span aria-hidden="true"> / </span>}
                {c.href ? <Link href={c.href}>{c.label}</Link> : <span aria-current="page">{c.label}</span>}
              </span>
            ))}
          </nav>
          <div className="ds-shell-spacer" />
          <ProjectSwitcher assets={assets} onNavigate={(id) => router.push(`/app/projects/${id}`)} />
          <InboxLink />
          <Link href="/app/dashboards" className="ds-shell-settings-link">Dashboards</Link>
          <Link href="/app/portfolios" className="ds-shell-settings-link">Business units</Link>
          <Link href="/app/reports" className="ds-shell-settings-link">Reports</Link>
          <Link href="/app/calendar" className="ds-shell-settings-link">Calendar</Link>
          <Link href="/app/components" className="ds-shell-settings-link">Components</Link>
          <Link href="/app/advisories" className="ds-shell-settings-link">Advisories</Link>
          <Link href="/app/risk-acceptances" className="ds-shell-settings-link">Approvals</Link>
          <Link href="/app/evidence" className="ds-shell-settings-link">Evidence</Link>
          <Link href="/app/mentions" className="ds-shell-settings-link">Mentions</Link>
          <Link href="/app/automation" className="ds-shell-settings-link">Automation</Link>
          <Link href="/app/connectors" className="ds-shell-settings-link">Connectors</Link>
          <Link href="/app/costs" className="ds-shell-settings-link">Costs</Link>
          <Link href="/app/settings" className="ds-shell-settings-link">Settings</Link>
          <Button onClick={() => setPaletteOpen(true)} aria-label="Open command palette">
            <span aria-hidden="true">⌘K</span>
          </Button>
          <Button onClick={() => setShortcutsOpen(true)} aria-label="Show keyboard shortcuts">?</Button>
        </header>
        <main className="ds-shell-main">{children}</main>

        <CommandPalette
          open={paletteOpen}
          onOpenChange={setPaletteOpen}
          assets={assets ?? []}
          onNavigate={(id) => {
            setPaletteOpen(false);
            router.push(`/app/projects/${id}`);
          }}
        />
        <ShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
      </div>
    </TooltipProvider>
    </ModeProvider>
  );
}

/** The inbox, with how many are unread (plan §49). Refreshes when the inbox page marks some read. */
function InboxLink() {
  const [unread, setUnread] = useState(0);
  useEffect(() => {
    const load = () => getInbox(true).then((i) => setUnread(typeof i?.unread === "number" ? i.unread : 0), () => setUnread(0));
    load();
    window.addEventListener("bulwark:inbox", load);
    return () => window.removeEventListener("bulwark:inbox", load);
  }, []);
  return (
    <Link href="/app/inbox" className="ds-shell-settings-link" aria-label={unread ? `Inbox, ${unread} unread` : "Inbox"}>
      Inbox{unread > 0 && <span className="ds-shell-count" aria-hidden="true">{unread > 99 ? "99+" : unread}</span>}
    </Link>
  );
}

function ProjectSwitcher({ assets, onNavigate }: { assets: AssetSummary[] | null; onNavigate: (id: string) => void }) {
  return (
    <DropdownMenuChildren trigger={<Button aria-label="Switch project">{"Projects ▾"}</Button>}>
      {assets === null && <div className="ds-dropdown-item" aria-disabled="true">Loading…</div>}
      {assets !== null && assets.length === 0 && <div className="ds-dropdown-item" aria-disabled="true">No projects scanned yet</div>}
      {assets?.map((a) => (
        <RadixDropdown.Item key={a.id} className="ds-dropdown-item" onSelect={() => onNavigate(a.id)}>
          {a.label}
        </RadixDropdown.Item>
      ))}
      <RadixDropdown.Separator className="ds-dropdown-separator" />
      <RadixDropdown.Item className="ds-dropdown-item" onSelect={() => onNavigate("")} disabled>
        Add a project (GitHub App, Week 30)
      </RadixDropdown.Item>
    </DropdownMenuChildren>
  );
}

function CommandPalette({
  open,
  onOpenChange,
  assets,
  onNavigate,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  assets: AssetSummary[];
  onNavigate: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const matches = useMemo(
    () => assets.filter((a) => a.label.toLowerCase().includes(query.trim().toLowerCase())).slice(0, 8),
    [assets, query],
  );

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      // Radix focuses the dialog content itself on open; move focus into the search field right after.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);
  useEffect(() => setActive(0), [query]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(i + 1, matches.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && matches[active]) {
      e.preventDefault();
      onNavigate(matches[active].id);
    }
  }

  return (
    <DsDialog open={open} onOpenChange={onOpenChange} title="Jump to a project" description="Command palette (§30.1) — more actions (issues, settings) arrive as those screens are built.">
      <input
        ref={inputRef}
        type="text"
        className="ds-palette-input"
        placeholder="Search projects by name…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={onKeyDown}
        aria-label="Search projects"
        aria-activedescendant={matches[active] ? `palette-item-${matches[active].id}` : undefined}
        role="combobox"
        aria-expanded="true"
        aria-controls="palette-list"
      />
      <ul id="palette-list" className="ds-palette-list" role="listbox">
        {matches.length === 0 && <li className="ds-palette-empty">No matching project</li>}
        {matches.map((a, i) => (
          <li
            key={a.id}
            id={`palette-item-${a.id}`}
            role="option"
            aria-selected={i === active}
            className={i === active ? "ds-palette-item active" : "ds-palette-item"}
            onMouseEnter={() => setActive(i)}
            onClick={() => onNavigate(a.id)}
          >
            {a.label}
          </li>
        ))}
      </ul>
    </DsDialog>
  );
}

const KEYMAP: { keys: string; action: string; status: "active" | "reserved" }[] = [
  { keys: "Cmd/Ctrl + K", action: "Command palette: jump to a project", status: "active" },
  { keys: "?", action: "Show all shortcuts", status: "active" },
  { keys: "Esc", action: "Close a dialog", status: "active" },
  { keys: "/", action: "Focus search", status: "reserved" },
  { keys: "j / k", action: "Next / previous issue, on an issue's own page (Week 35)", status: "active" },
  { keys: "Enter", action: "Open the focused issue", status: "reserved" },
  { keys: "x", action: "Select the focused issue", status: "reserved" },
  { keys: "f", action: "Review its fix", status: "reserved" },
  { keys: "n", action: "Mark as not a risk (asks for a reason)", status: "reserved" },
  { keys: "a", action: "Accept risk (asks for an expiry date)", status: "reserved" },
  { keys: "g then i", action: "Go to Issues", status: "reserved" },
];

function ShortcutsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <DsDialog open={open} onOpenChange={onOpenChange} title="Keyboard shortcuts" description="The full map from plan §30.1. Rows marked “reserved” aren't wired on any screen yet.">
      <table className="ds-shortcuts-table">
        <thead>
          <tr>
            <th>Key</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {KEYMAP.map((row) => (
            <tr key={row.keys} className={row.status === "reserved" ? "reserved" : undefined}>
              <td><kbd>{row.keys}</kbd></td>
              <td>
                {row.action}
                {row.status === "reserved" && <span className="ds-shortcuts-tag"> Not on this screen yet</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </DsDialog>
  );
}
