"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, getAssetOverview } from "@/lib/api";
import type { ProjectOverview as ProjectOverviewData } from "@/lib/types";
import { SeverityBadge } from "@/design-system/severity";
import { WhyRankedTrigger } from "@/design-system/why-ranked";
import { Button } from "@/design-system/primitives/Button";
import "./project-overview.css";

/**
 * Plan §28.1's project overview screen: verdict, fix-first queue, since-previous-scan deltas, and
 * what the latest scan covered — Layout A from the Week 31 sketch (docs/ux-overview-layouts.md):
 * a wide primary column beside a persistent sidebar, chosen for progressive disclosure and
 * keyboard-triage stability. Nothing here is fabricated data: every field traces back to
 * api/schemas.py's ProjectOverview, itself derived from real scans (see
 * docs/v2-week33-verification.md).
 */
export function ProjectOverview({ assetId }: { assetId: string }) {
  const [data, setData] = useState<ProjectOverviewData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    getAssetOverview(assetId).then(
      (d) => { if (!cancelled) setData(d); },
      (e) => { if (!cancelled) setError(e instanceof ApiError ? e.message : "Failed to load this project"); },
    );
    return () => { cancelled = true; };
  }, [assetId]);

  if (error) return <div className="ds-ov-empty" role="alert">{error}</div>;
  if (!data) return <div className="ds-ov-empty" role="status" aria-live="polite">Loading…</div>;

  if (data.latest_scan_id === null) {
    return (
      <div className="ds-ov-empty">
        <p>{data.asset.label} has been added but hasn&apos;t finished a scan yet.</p>
      </div>
    );
  }

  const { fix_first, more_at_lower_risk, since_previous_scan, trend, scanned } = data;
  const maxOpen = Math.max(1, ...trend.map((p) => p.open_count));

  return (
    <div className="ds-ov">
      <div className="ds-ov-crumbline">
        {data.asset.label} <span aria-hidden="true">·</span>{" "}
        <Link href={`/scans/${data.latest_scan_id}`}>full scan report</Link>
      </div>

      <div className="ds-ov-verdict">
        <h1>
          {data.verdict_count === 0
            ? "No critical or high-risk issues right now."
            : `${data.verdict_count} issue${data.verdict_count === 1 ? "" : "s"} put this project at real risk.`}
        </h1>
        {fix_first.length > 0 && <p>Ranked by severity and how likely each one is to be exploited. Start with the first.</p>}
      </div>

      <div className="ds-ov-grid">
        <section aria-labelledby="fix-first-h" className="ds-ov-fixfirst">
          <div className="ds-ov-label" id="fix-first-h">Fix first</div>
          {fix_first.length === 0 && <p className="ds-ov-empty-inline">Nothing open in the latest scan.</p>}
          <ol className="ds-ov-list">
            {fix_first.map((f, i) => (
              <li key={f.id} className="ds-ov-item">
                <span className="ds-ov-rank" aria-hidden="true">{i + 1}</span>
                <div className="ds-ov-item-main">
                  <WhyRankedTrigger factors={f.scoring.risk_factors ?? []}>
                    <span className="ds-ov-item-title">{f.title}</span>
                  </WhyRankedTrigger>
                  <div className="ds-ov-item-meta">
                    <SeverityBadge severity={severityKey(f.scoring.normalized_severity)} reachable={f.scoring.reachable !== false} />
                    <code>{f.location.path}:{f.location.start_line}</code>
                  </div>
                </div>
                <Link href={`/scans/${data.latest_scan_id}`} className="ds-ov-item-action">View →</Link>
              </li>
            ))}
          </ol>
          {more_at_lower_risk > 0 && (
            <p className="ds-ov-more">
              {more_at_lower_risk} more issue{more_at_lower_risk === 1 ? "" : "s"} at lower risk{" "}
              <Link href={`/scans/${data.latest_scan_id}`}>View all</Link>
            </p>
          )}
        </section>

        <aside className="ds-ov-sidebar">
          <div>
            <div className="ds-ov-label">Since previous scan</div>
            <p>
              {since_previous_scan.fixed} fixed · {since_previous_scan.new} new · {since_previous_scan.returned} returned
            </p>
            {trend.length > 1 && (
              <div className="ds-ov-sparkline" role="img" aria-label={`Open issues over the last ${trend.length} scans: ${trend.map((p) => p.open_count).join(", ")}`}>
                {trend.map((p) => (
                  <span key={p.scan_id} style={{ height: `${Math.round((p.open_count / maxOpen) * 100)}%` }} />
                ))}
              </div>
            )}
          </div>

          <div>
            <div className="ds-ov-label">What was scanned</div>
            <ul className="ds-ov-scanned">
              {scanned.map((t) => (
                <li key={t.tool} className={t.status !== "ok" ? "ds-ov-scanned-notok" : undefined}>
                  {t.tool} <span>{t.status}{t.status === "ok" ? ` · ${t.findings} finding${t.findings === 1 ? "" : "s"}` : ""}</span>
                </li>
              ))}
            </ul>
          </div>
        </aside>
      </div>

      <div className="ds-ov-footnote">
        <Button onClick={() => window.location.reload()}>Refresh</Button>
      </div>
    </div>
  );
}

function severityKey(s: string): "critical" | "high" | "medium" | "low" | "info" {
  return s.toLowerCase() as "critical" | "high" | "medium" | "low" | "info";
}
