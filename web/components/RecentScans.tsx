"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { listScans } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import type { ScanSummary } from "@/lib/types";
import { SeverityCounts, StatusBadge } from "./Badges";

export function RecentScans() {
  const [rows, setRows] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listScans().then(setRows, (e) => setError(e instanceof Error ? e.message : "Failed to load"));
  }, []);

  return (
    <section className="cell stack" aria-labelledby="recent-h">
      <span className="eyebrow" id="recent-h">Recent scans</span>
      {error && <p className="error" role="alert">{error}</p>}
      {rows === null && !error && (
        <div aria-busy="true" aria-label="Loading recent scans" className="skeleton-list">
          {[0, 1, 2].map((i) => <span key={i} className="sk sk-row" />)}
        </div>
      )}
      {rows?.length === 0 && (
        <div className="empty">
          <p className="muted">No scans yet. Start one on the left, or take a look at what a finished report looks like.</p>
          <Link href="/demo" className="btn sm">View a sample scan →</Link>
        </div>
      )}
      {rows && rows.length > 0 && (
        <div className="scroll">
          <table>
            <thead><tr><th scope="col">Source</th><th scope="col">Status</th><th scope="col">Findings</th><th scope="col">Started</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td><Link href={`/scans/${r.id}`} className="src-link wrap">{r.source_label}</Link></td>
                  <td><StatusBadge status={r.status} /></td>
                  <td>{r.status === "queued" || r.status === "running" ? <span className="muted">…</span> : <span className="cell-num">{r.unique_findings} <SeverityCounts counts={r.severity_counts} /></span>}</td>
                  <td><time dateTime={r.created_at} title={new Date(r.created_at).toLocaleString()} className="muted">{relativeTime(r.created_at)}</time></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
