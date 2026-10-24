"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { listAssets } from "@/lib/api";
import { projectName } from "@/lib/format";
import type { AssetSummary } from "@/lib/types";
import { DropdownMenuChildren } from "@/design-system/primitives/DropdownMenu";
import { Dialog as DsDialog } from "@/design-system/primitives/Dialog";
import { Button } from "@/design-system/primitives/Button";
import { TooltipProvider } from "@/design-system/primitives/Tooltip";
import { ModeProvider } from "@/design-system/mode";
import * as RadixDropdown from "@radix-ui/react-dropdown-menu";
import "@/design-system/fonts.css";
import "@/design-system/tokens.css";
import { ProjectNav, projectFromPath } from "./ProjectNav";
import "./shell.css";

export type Crumb = { label: string; href?: string };

/**
 * The bar under the site header on the app's screens: breadcrumbs, a project switcher, the command
 * palette (Cmd/Ctrl+K) and shortcut help (?) — plan §27, §30.1. The app's sections themselves are
 * in the site header (components/site/AppNav.tsx), so there is one navigation bar, not two.
 */
/** `title`, when given, heads the page with the site's eyebrow and an h1, for screens whose own
 * component doesn't open with one. */
export function AppShell({ crumbs, title, eyebrow, children }: { crumbs: Crumb[]; title?: string; eyebrow?: string; children: ReactNode }) {
  const router = useRouter();
  const path = usePathname() ?? "";
  const [assets, setAssets] = useState<AssetSummary[] | null>(null);

  // On a project's pages: its name in the breadcrumbs (they say "Project" until the list arrives) and
  // its tabs under the bar. `undefined` while loading, `null` for a project not in the list.
  const proj = projectFromPath(path);
  const asset = proj && assets !== null ? assets.find((a) => a.id === proj.id) ?? null : undefined;
  const projectHref = proj ? `/app/projects/${proj.id}` : null;
  const shown: Crumb[] = crumbs.map((c) => (c.href === projectHref && asset ? { ...c, label: projectName(asset.label) } : c));
  if (proj && asset && !crumbs.some((c) => c.href === projectHref)) {
    // A page whose crumbs skip the project (Projects / Issues) still says which project it is.
    const name = projectName(asset.label);
    if (proj.sub === "") shown.push({ label: name });
    else shown.splice(shown[0]?.href === "/app/projects" ? 1 : 0, 0, { label: name, href: projectHref! });
  }
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
        <div className="ds-shell-bar">
          <nav aria-label="Breadcrumb" className="ds-shell-crumbs">
            {shown.map((c, i) => (
              <span key={i}>
                {i > 0 && <span aria-hidden="true" className="ds-shell-sep">/</span>}
                {c.href ? <Link href={c.href}>{c.label}</Link> : <span aria-current="page">{c.label}</span>}
              </span>
            ))}
          </nav>
          <div className="ds-shell-tools">
            <ProjectSwitcher assets={assets} onNavigate={(id) => router.push(`/app/projects/${id}`)} />
            {/* Named by its hidden text, not aria-label: axe 4.14 requires an aria-label to contain the
                visible text, and "⌘K" is a shortcut hint, not a name. */}
            <Button onClick={() => setPaletteOpen(true)} aria-keyshortcuts="Meta+K Control+K">
              <span className="sr-only">Open command palette</span>
              <span aria-hidden="true">⌘K</span>
            </Button>
            <Button onClick={() => setShortcutsOpen(true)} aria-label="Show keyboard shortcuts">?</Button>
          </div>
        </div>
        {proj && <ProjectNav id={proj.id} sub={proj.sub} asset={asset} />}
        <div className="ds-shell-main">
          {title && (
            <div className="ds-page-head">
              {eyebrow && <span className="eyebrow">{eyebrow}</span>}
              <h1>{title}</h1>
            </div>
          )}
          {children}
        </div>

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

function ProjectSwitcher({ assets, onNavigate }: { assets: AssetSummary[] | null; onNavigate: (id: string) => void }) {
  return (
    <DropdownMenuChildren trigger={<Button aria-label="Switch project">{"Switch project ▾"}</Button>}>
      {assets === null && <div className="ds-dropdown-item" aria-disabled="true">Loading…</div>}
      {assets !== null && assets.length === 0 && <div className="ds-dropdown-item" aria-disabled="true">No projects scanned yet</div>}
      {assets?.map((a) => (
        <RadixDropdown.Item key={a.id} className="ds-dropdown-item" onSelect={() => onNavigate(a.id)} title={a.label}>
          {projectName(a.label)}
        </RadixDropdown.Item>
      ))}
      <RadixDropdown.Separator className="ds-dropdown-separator" />
      <RadixDropdown.Item asChild className="ds-dropdown-item">
        <Link href="/app/projects">All projects</Link>
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
    <DsDialog open={open} onOpenChange={onOpenChange} title="Jump to a project" description="Type part of a project's name, then press Enter.">
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
            {projectName(a.label)}
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
  { keys: "j / k", action: "Next / previous issue, on an issue's own page", status: "active" },
  { keys: "Enter", action: "Open the focused issue", status: "reserved" },
  { keys: "x", action: "Select the focused issue", status: "reserved" },
  { keys: "f", action: "Review its fix", status: "reserved" },
  { keys: "n", action: "Mark as not a risk (asks for a reason)", status: "reserved" },
  { keys: "a", action: "Accept risk (asks for an expiry date)", status: "reserved" },
  { keys: "g then i", action: "Go to Issues", status: "reserved" },
];

function ShortcutsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <DsDialog open={open} onOpenChange={onOpenChange} title="Keyboard shortcuts" description="Shortcuts marked “not on this screen yet” are planned but not available yet.">
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
