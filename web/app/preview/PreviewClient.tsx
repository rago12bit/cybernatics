"use client";

import { ScanPage } from "@/components/ScanPage";
import { FindingsTable } from "@/components/FindingsTable";
import { SeverityCounts, StatusBadge } from "@/components/Badges";
import { ToolCards } from "@/components/ToolCards";
import { dedupSummary, findingsQueryString, PAGE_SIZE, severityRank } from "@/lib/format";
import type { Finding, FindingsPage, FindingsQuery, ScanView } from "@/lib/types";
import data from "./data.json";

const scan = data.scan as unknown as ScanView;
const all = data.findings as unknown as Finding[];

// Mirrors the API's filtering/sorting so the table behaves like the real thing.
async function fetchFindings(_id: string, q: FindingsQuery): Promise<FindingsPage> {
  void findingsQueryString;
  let rows = all.filter(
    (f) =>
      (q.severity.length === 0 || q.severity.includes(f.scoring.normalized_severity)) &&
      (!q.category || f.taxonomy.category === q.category) &&
      (!q.tool || f.evidence.reported_by.includes(q.tool)) &&
      (!q.path.trim() || f.location.path.includes(q.path.trim())),
  );
  rows = [...rows].sort((a, b) =>
    q.sort === "path"
      ? a.location.path.localeCompare(b.location.path) || a.location.start_line - b.location.start_line
      : severityRank(b.scoring.normalized_severity) - severityRank(a.scoring.normalized_severity) ||
        a.location.path.localeCompare(b.location.path),
  );
  return { total: rows.length, limit: PAGE_SIZE, offset: q.page * PAGE_SIZE, items: rows.slice(q.page * PAGE_SIZE, (q.page + 1) * PAGE_SIZE) };
}

export function PreviewClient() {
  const running: ScanView = {
    ...scan,
    status: "running",
    finished_at: null,
    tool_status: { bandit: scan.tool_status["bandit"]!, gitleaks: scan.tool_status["gitleaks"]! },
  };
  void ScanPage;
  return (
    <>
      <section className="card" aria-label="In progress (preview)">
        <div className="scan-head">
          <h1>github.com/owner/repo</h1>
          <StatusBadge status="running" />
        </div>
        <p className="muted small">Live: updates arrive as each scanner finishes.</p>
        <ToolCards scan={running} />
      </section>

      <section className="card" aria-labelledby="scan-h">
        <div className="scan-head">
          <h1 id="scan-h">{scan.source_label}</h1>
          <StatusBadge status="completed" />
        </div>
        <p className="muted small">Finished 25 Sep 2026, 00:00</p>
        <ToolCards scan={scan} />
        <div className="summary">
          <div><span className="muted small">Severity</span><br /><SeverityCounts counts={scan.severity_counts} /></div>
          <p className="dedup">{dedupSummary(scan)}</p>
          <p className="muted small">Raw scanner output was not stored for this scan because secrets were found; it could echo them.</p>
        </div>
      </section>
      <FindingsTable scan={scan} version={0} fetchFindings={fetchFindings} />
    </>
  );
}
