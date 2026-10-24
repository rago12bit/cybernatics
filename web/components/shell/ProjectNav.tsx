"use client";

import Link from "next/link";
import * as RadixDropdown from "@radix-ui/react-dropdown-menu";
import { projectHost, projectName } from "@/lib/format";
import type { AssetSummary } from "@/lib/types";

/* A project's own pages, on every one of them: its name, then tabs for the pages people use most and
   a More menu for the rest. Before, only the overview listed them (16 small links in two rows), so
   moving from SLA to Tickets meant going back to the overview first. */

type Tab = { path: string; label: string; hint?: string };

const TABS: Tab[] = [
  { path: "", label: "Overview" },
  { path: "/issues", label: "Issues" },
  { path: "/dependencies", label: "Dependencies" },
  { path: "/threat-model", label: "Threat model" },
  { path: "/asvs", label: "ASVS" },
  { path: "/sla", label: "SLA" },
  { path: "/priority", label: "Priority" },
  { path: "/tickets", label: "Tickets" },
];

const MORE: { id: string; label: string; tabs: Tab[] }[] = [
  { id: "scans", label: "Findings", tabs: [
    { path: "/compare", label: "Compare scans", hint: "What changed between two scans" },
    { path: "/import", label: "Import a report", hint: "From a scanner you already run" },
    { path: "/findings/new", label: "Record a finding", hint: "From a pen test or a review" },
    { path: "/matching", label: "Matching", hint: "How each source's findings merge" },
  ] },
  { id: "review", label: "Review", tabs: [
    { path: "/engagements", label: "Engagements", hint: "Pen tests and reviews, with checklists" },
    { path: "/hypotheses", label: "Hypotheses", hint: "Leads to confirm or rule out" },
    { path: "/attack-paths", label: "Attack paths", hint: "How issues chain together" },
    { path: "/vex", label: "VEX", hint: "Exploitability statements" },
  ] },
];

const WEB: Tab[] = [
  { path: "/verify", label: "Verify ownership", hint: "Prove you own the site before a scan" },
  { path: "/map", label: "Site map", hint: "What the crawler found" },
  { path: "/campaigns", label: "Campaigns", hint: "Passive and active web scans" },
];

/** The project id and the page under it, for any `/app/projects/<id>/...` path (not `new-web`). */
export function projectFromPath(path: string): { id: string; sub: string } | null {
  const m = /^\/app\/projects\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z0-9][a-z0-9-]{0,63})(\/.*)?$/i.exec(path);
  if (!m || m[1] === "new-web") return null;
  return { id: m[1]!, sub: (m[2] ?? "").replace(/\/+$/, "") };
}

function isActive(sub: string, path: string): boolean {
  return path === "" ? sub === "" : sub === path || sub.startsWith(`${path}/`);
}

export function ProjectNav({ id, sub, asset }: { id: string; sub: string; asset: AssetSummary | null | undefined }) {
  const base = `/app/projects/${id}`;
  const groups = asset?.source_type === "web" ? [...MORE, { id: "web", label: "Web target", tabs: WEB }] : MORE;
  const inMore = groups.some((g) => g.tabs.some((t) => isActive(sub, t.path)));
  const host = asset ? projectHost(asset.label) ?? (asset.source_type === "web" ? "Web target" : null) : null;

  return (
    <div className="ds-proj">
      <div className="ds-proj-id">
        {asset === undefined ? (
          <span className="sk sk-m ds-proj-sk" aria-hidden="true" />
        ) : (
          <>
            {host && <span className="ds-proj-host">{host}</span>}
            <Link href={base} className="ds-proj-name" title={asset?.label}>{asset ? projectName(asset.label) : "Project"}</Link>
          </>
        )}
        {asset?.latest_scan_id && (
          <Link href={`/scans/${asset.latest_scan_id}`} className="ds-proj-report">Latest scan report →</Link>
        )}
      </div>
      <nav aria-label="This project" className="ds-proj-tabs">
        {TABS.map((t) => (
          <Link key={t.path} href={base + t.path} aria-current={isActive(sub, t.path) ? "page" : undefined}>{t.label}</Link>
        ))}
        <RadixDropdown.Root modal={false}>
          <RadixDropdown.Trigger className="ds-proj-more" data-current={inMore || undefined}>
            More
            <svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" focusable="false">
              <path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </RadixDropdown.Trigger>
          <RadixDropdown.Portal>
            <RadixDropdown.Content className="nav-more-menu ds-proj-menu" sideOffset={8} align="end" collisionPadding={16} loop>
              <div className="nav-more-groups">
                {groups.map((g) => (
                  <RadixDropdown.Group key={g.id} className="nav-more-group" aria-labelledby={`proj-more-${g.id}`}>
                    <RadixDropdown.Label className="nav-more-label" id={`proj-more-${g.id}`}>{g.label}</RadixDropdown.Label>
                    {g.tabs.map((t) => (
                      <RadixDropdown.Item key={t.path} asChild className="nav-more-item">
                        <Link href={base + t.path} aria-current={isActive(sub, t.path) ? "page" : undefined}>
                          <span className="t">{t.label}</span>
                          {t.hint && <span className="h">{t.hint}</span>}
                        </Link>
                      </RadixDropdown.Item>
                    ))}
                  </RadixDropdown.Group>
                ))}
              </div>
            </RadixDropdown.Content>
          </RadixDropdown.Portal>
        </RadixDropdown.Root>
      </nav>
    </div>
  );
}
