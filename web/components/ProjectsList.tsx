"use client";

import Link from "next/link";
import { useEffect, useId, useMemo, useState } from "react";
import { ApiError, listAssets } from "@/lib/api";
import { formatDateTime, projectHost, projectName, relativeTime } from "@/lib/format";
import type { AssetSummary } from "@/lib/types";
import { EmptyState } from "@/design-system/primitives/EmptyState";
import { StatusBadge } from "./Badges";
import "./project-overview.css";

type Sort = "recent" | "issues" | "name";

/** Plan §27's "Projects" screen: one row per distinct repository or site (ADR-0012), most recently
 * scanned first. Each row is one link to the project's overview, named the way people say it
 * (`acme/payments-api`, not its clone URL), with its open issues and when it was last scanned. */
export function ProjectsList() {
  const id = useId();
  const [assets, setAssets] = useState<AssetSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<Sort>("recent");
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    listAssets().then(setAssets, (e) => setError(e instanceof ApiError ? e.message : "Could not load your projects."));
    const tick = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(tick);
  }, []);

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const rows = (assets ?? []).filter((a) => !q || a.label.toLowerCase().includes(q));
    const by: Record<Sort, (a: AssetSummary, b: AssetSummary) => number> = {
      recent: (a, b) => Date.parse(b.last_scanned_at) - Date.parse(a.last_scanned_at),
      issues: (a, b) => b.open_issue_count - a.open_issue_count,
      name: (a, b) => projectName(a.label).localeCompare(projectName(b.label)),
    };
    return [...rows].sort(by[sort]);
  }, [assets, filter, sort]);

  const actions = (
    <div className="ds-pl-actions">
      <Link href="/app/scan" className="ds-button primary">Scan a repository</Link>
      <Link href="/app/projects/new-web" className="ds-button">Add a web target</Link>
    </div>
  );

  if (error) return <div className="ds-ov-empty" role="alert">{error}</div>;
  if (!assets) {
    return (
      <div role="status" aria-busy="true">
        <span className="sr-only">Loading projects…</span>
        <ul className="ds-pl" aria-hidden="true">
          {[0, 1, 2].map((i) => (
            <li key={i} className="ds-pl-row ds-pl-sk">
              <span className="ds-pl-name"><span className="sk sk-s" /><span className="sk sk-m" /></span>
              <span className="sk sk-s" />
              <span className="sk sk-m" />
            </li>
          ))}
        </ul>
      </div>
    );
  }
  if (assets.length === 0) {
    return (
      <EmptyState
        title="No projects yet"
        actions={<>
          <Link href="/app/scan" className="ds-button primary">Scan a repository →</Link>
          <Link href="/app/projects/new-web" className="ds-button">Add a web target</Link>
        </>}
      >
        <p>A project appears here after its first scan, or when you import a report into it. A scan of a public repository takes about two minutes.</p>
      </EmptyState>
    );
  }

  return (
    <div className="ds-pl-wrap">
      <div className="ds-pl-bar">
        {assets.length > 3 ? (
          <div className="ds-pl-tools">
            <label htmlFor={`${id}-q`} className="sr-only">Filter projects</label>
            <input id={`${id}-q`} type="search" placeholder="Filter by name…" value={filter} onChange={(e) => setFilter(e.target.value)} autoComplete="off" />
            <label htmlFor={`${id}-s`} className="sr-only">Sort projects</label>
            <select id={`${id}-s`} value={sort} onChange={(e) => setSort(e.target.value as Sort)}>
              <option value="recent">Recently scanned</option>
              <option value="issues">Most open issues</option>
              <option value="name">Name</option>
            </select>
          </div>
        ) : <span />}
        {actions}
      </div>
      <p className="ds-pl-count" aria-live="polite">
        {shown.length === assets.length ? `${assets.length} project${assets.length === 1 ? "" : "s"}` : `${shown.length} of ${assets.length} projects`}
      </p>
      {shown.length === 0 ? (
        <EmptyState compact title={`No project matches “${filter.trim()}”`}>
          <p>Names are matched anywhere, so part of the repository or site name is enough.</p>
        </EmptyState>
      ) : (
        <ul className="ds-pl" aria-label="Projects">
          {shown.map((a) => {
            const host = projectHost(a.label) ?? (a.source_type === "web" ? "Web target" : a.source_type === "archive" ? "Upload" : null);
            return (
              <li key={a.id}>
                <Link href={`/app/projects/${a.id}`} className="ds-pl-row" title={a.label}>
                  <span className="ds-pl-name">
                    {host && <span className="ds-pl-host">{host}</span>}
                    <span className="ds-pl-title">{projectName(a.label)}</span>
                  </span>
                  <span className="ds-pl-issues">
                    <span className={a.open_issue_count > 0 ? "ds-pl-num" : "ds-pl-num zero"}>{a.open_issue_count.toLocaleString("en-US")}</span>
                    <span className="ds-pl-unit">open issue{a.open_issue_count === 1 ? "" : "s"}</span>
                  </span>
                  <span className="ds-pl-scan">
                    {a.latest_scan_status ? <StatusBadge status={a.latest_scan_status} /> : <span className="ds-pl-unit">No completed scan</span>}
                    <time dateTime={a.last_scanned_at} title={formatDateTime(a.last_scanned_at)}>{relativeTime(a.last_scanned_at, now)}</time>
                  </span>
                  <span className="ds-pl-go" aria-hidden="true">→</span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
