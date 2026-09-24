"use client";

import Link from "next/link";
import { dedupSummary, isTerminal } from "@/lib/format";
import { useScan } from "@/lib/useScan";
import { SeverityCounts, StatusBadge } from "./Badges";
import { FindingsTable } from "./FindingsTable";
import { ToolCards } from "./ToolCards";

export function ScanPage({ id }: { id: string }) {
  const { scan, error, connection, version } = useScan(id);

  if (error && !scan) return <p className="error" role="alert">{error}</p>;
  if (!scan) return <p className="muted" role="status">Loading scan…</p>;
  const done = isTerminal(scan.status);

  return (
    <>
      <p><Link href="/">← All scans</Link></p>
      <section className="card" aria-labelledby="scan-h">
        <div className="scan-head">
          <h1 id="scan-h">{scan.source_label}</h1>
          <StatusBadge status={scan.status} />
        </div>
        <p className="muted small" role="status" aria-live="polite">
          {done ? `Finished ${scan.finished_at ? new Date(scan.finished_at).toLocaleString() : ""}` : connection === "live" ? "Live: updates arrive as each scanner finishes." : connection === "polling" ? "Refreshing every few seconds…" : "Connecting…"}
        </p>
        {scan.error && <p className="error" role="alert">{scan.error}</p>}
        <ToolCards scan={scan} />
        {done && scan.status !== "failed" && (
          <div className="summary">
            <div><span className="muted small">Severity</span><br /><SeverityCounts counts={scan.severity_counts} /></div>
            <p className="dedup">{dedupSummary(scan)}</p>
          </div>
        )}
        {Object.values(scan.tool_status).some((t) => t.raw_artifact === "withheld") && (
          <p className="muted small">Raw scanner output was not stored for this scan because secrets were found; it could echo them.</p>
        )}
        {scan.status === "partial" && <p className="warn">Some scanners failed or timed out. Results below are from the scanners that finished.</p>}
      </section>
      {done && scan.status !== "failed" && <FindingsTable scan={scan} version={version} />}
    </>
  );
}
