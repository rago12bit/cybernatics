"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { listScans } from "@/lib/api";
import { relativeTime } from "@/lib/format";
import type { ScanSummary } from "@/lib/types";
import { SeverityCounts, StatusBadge } from "./Badges";

export function RecentScans() {
  const [rows, setRows] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [now, setNow] = useState(() => Date.now());

  // A failed refresh keeps the list you already have; only a failed first load shows an error.
  const load = useCallback(() => {
    listScans().then(
      (r) => { setRows(r); setError(null); },
      (e) => setError(e instanceof Error ? e.message : "Failed to load"),
    );
  }, []);
  useEffect(() => { load(); }, [load]);

  // Follow scans that are still queued or running, and stop as soon as nothing is.
  const active = rows?.some((r) => r.status === "queued" || r.status === "running") ?? false;
  useEffect(() => {
    if (!active) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [active, load]);

  // Coming back to the tab refreshes the list; "3 min ago" labels keep counting without a reload.
  useEffect(() => {
    const onVisible = () => { if (document.visibilityState === "visible") { load(); setNow(Date.now()); } };
    document.addEventListener("visibilitychange", onVisible);
    const tick = setInterval(() => setNow(Date.now()), 30_000);
    return () => { document.removeEventListener("visibilitychange", onVisible); clearInterval(tick); };
  }, [load]);

  return (
    <section className="cell stack" aria-labelledby="recent-h">
      <span className="eyebrow" id="recent-h">Recent scans</span>
      {error && rows === null && <p className="error" role="alert">{error}</p>}
      {rows === null && !error && (
        <div aria-busy="true" aria-label="Loading recent scans" className="skeleton-list">
          {[0, 1, 2].map((i) => <span key={i} className="sk sk-row" />)}
        </div>
      )}
      {rows?.length === 0 && (
        <div className="empty">
          <p className="muted">No scans yet. Start one on the left, or take a look at what a finished report looks like.</p>
          <Link href="/" className="btn sm">View a sample scan →</Link>
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
                  <td><time dateTime={r.created_at} title={new Date(r.created_at).toLocaleString()} className="muted">{relativeTime(r.created_at, now)}</time></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
