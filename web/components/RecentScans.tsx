"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { listScans } from "@/lib/api";
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
      {rows === null && !error && <p className="muted">Loading…</p>}
      {rows?.length === 0 && <p className="muted">No scans yet. Start one above.</p>}
      {rows && rows.length > 0 && (
        <div className="scroll">
          <table>
            <thead>
              <tr><th>Source</th><th>Status</th><th>Findings</th><th>Started</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td><Link href={`/scans/${r.id}`}>{r.source_label}</Link></td>
                  <td><StatusBadge status={r.status} /></td>
                  <td>{r.unique_findings} <SeverityCounts counts={r.severity_counts} /></td>
                  <td><time dateTime={r.created_at}>{new Date(r.created_at).toLocaleString()}</time></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
