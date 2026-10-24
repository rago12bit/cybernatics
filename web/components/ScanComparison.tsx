"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { ApiError, compareScans, getAssetOverview } from "@/lib/api";
import type { ComparedIssue, ProjectOverview, ScanComparison as ScanComparisonData } from "@/lib/types";
import { SeverityBadge } from "@/design-system/severity";
import { EmptyState } from "@/design-system/primitives/EmptyState";
import { formatDateTime } from "@/lib/format";
import "./scan-comparison.css";

function severityKey(s: string): "critical" | "high" | "medium" | "low" | "info" {
  return s.toLowerCase() as "critical" | "high" | "medium" | "low" | "info";
}

function label(side: ScanComparisonData["earlier"]): string {
  const when = side.finished_at ? formatDateTime(side.finished_at) : "in progress";
  const pr = side.github_pr_number ? ` (PR #${side.github_pr_number})` : "";
  return `${side.source_label}${pr} — ${when}`;
}

interface Column {
  key: keyof Pick<ScanComparisonData, "new" | "fixed" | "reintroduced" | "unchanged">;
  title: string;
  empty: string;
}

const COLUMNS: Column[] = [
  { key: "new", title: "New", empty: "Nothing new between these two scans." },
  { key: "reintroduced", title: "Reintroduced", empty: "Nothing came back." },
  { key: "fixed", title: "Fixed", empty: "Nothing was fixed between these two scans." },
  { key: "unchanged", title: "Unchanged", empty: "Nothing stayed the same." },
];

function IssueList({ items, assetId }: { items: ComparedIssue[]; assetId: string }) {
  if (items.length === 0) return null;
  return (
    <ul className="ds-cmp-list">
      {items.map((i) => (
        <li key={i.id} className="ds-cmp-item">
          <SeverityBadge severity={severityKey(i.severity)} />
          <Link href={`/app/projects/${assetId}/issues/${i.id}`} className="ds-cmp-item-title">
            {i.title}
          </Link>
          <code className="ds-cmp-item-path">{i.path}</code>
        </li>
      ))}
    </ul>
  );
}

/**
 * Plan §28.6's scan comparison screen: two of a project's scans, side by side -- new, fixed,
 * reintroduced and unchanged issues, with the two scans' own labels standing in for a full commit
 * range (core/persistence/repo.py's Scan doesn't track a resolved commit SHA yet; source_label,
 * the finish time, and a PR number when there is one are what's actually available today).
 */
export function ScanComparison({ assetId }: { assetId: string }) {
  const [overview, setOverview] = useState<ProjectOverview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [earlierId, setEarlierId] = useState("");
  const [laterId, setLaterId] = useState("");
  const [data, setData] = useState<ScanComparisonData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getAssetOverview(assetId).then(
      (d) => {
        if (cancelled) return;
        setOverview(d);
        if (d.trend.length >= 2) {
          setEarlierId(d.trend[d.trend.length - 2]!.scan_id);
          setLaterId(d.trend[d.trend.length - 1]!.scan_id);
        }
      },
      (e) => { if (!cancelled) setOverviewError(e instanceof ApiError ? e.message : "Failed to load this project"); },
    );
    return () => { cancelled = true; };
  }, [assetId]);

  useEffect(() => {
    if (!earlierId || !laterId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    compareScans(laterId, earlierId).then(
      (d) => { if (!cancelled) { setData(d); setLoading(false); } },
      (e) => {
        if (cancelled) return;
        setError(e instanceof ApiError ? e.message : "Failed to compare these scans");
        setLoading(false);
      },
    );
    return () => { cancelled = true; };
  }, [earlierId, laterId]);

  const options = useMemo(() => overview?.trend ?? [], [overview]);

  if (overviewError) return <div className="ds-cmp-empty" role="alert">{overviewError}</div>;
  if (!overview) return <div className="ds-cmp" role="status" aria-busy="true"><span className="sr-only">Loading…</span></div>;
  if (options.length < 2) {
    return (
      <EmptyState
        title="Nothing to compare yet"
        actions={<Link href="/app/scan" className="ds-button primary">Scan it again →</Link>}
      >
        <p>
          This project needs at least two finished scans to compare. It has {options.length === 1 ? "one" : "none"} so far.
          The next scan shows what was fixed, what is new and what came back.
        </p>
      </EmptyState>
    );
  }

  return (
    <div className="ds-cmp">
      <div className="ds-cmp-picker">
        <label>
          Earlier scan
          <select value={earlierId} onChange={(e) => setEarlierId(e.target.value)}>
            {options.map((p) => (
              <option key={p.scan_id} value={p.scan_id}>
                {formatDateTime(p.finished_at)} ({p.open_count} open)
              </option>
            ))}
          </select>
        </label>
        <label>
          Later scan
          <select value={laterId} onChange={(e) => setLaterId(e.target.value)}>
            {options.map((p) => (
              <option key={p.scan_id} value={p.scan_id}>
                {formatDateTime(p.finished_at)} ({p.open_count} open)
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && <p role="alert" className="error">{error}</p>}
      {loading && <p role="status">Comparing…</p>}

      {data && !loading && (
        <>
          <p className="ds-cmp-range">
            {label(data.earlier)} <span aria-hidden="true">→</span> {label(data.later)}
          </p>
          <div className="ds-cmp-grid">
            {COLUMNS.map((col) => (
              <section key={col.key} aria-labelledby={`cmp-${col.key}-h`}>
                <div className="ds-cmp-col-title" id={`cmp-${col.key}-h`}>
                  {col.title} <span className="ds-cmp-count">{data[col.key].length}</span>
                </div>
                {data[col.key].length === 0 ? (
                  <p className="ds-cmp-empty-inline">{col.empty}</p>
                ) : (
                  <IssueList items={data[col.key]} assetId={assetId} />
                )}
              </section>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
