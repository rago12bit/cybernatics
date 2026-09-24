"use client";

import { ScanReport } from "@/components/ScanReport";
import { PAGE_SIZE, severityRank } from "@/lib/format";
import type { Finding, FindingsPage, FindingsQuery, ScanView } from "@/lib/types";
import data from "./data.json";

const scan = data.scan as unknown as ScanView;
const all = data.findings as unknown as Finding[];

// Mirrors the API's filtering/sorting so the table behaves like the real thing.
async function fetchFindings(_id: string, q: FindingsQuery): Promise<FindingsPage> {
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
    source_label: "github.com/owner/repo",
    status: "running",
    finished_at: null,
    tool_status: { bandit: scan.tool_status["bandit"]!, gitleaks: scan.tool_status["gitleaks"]! },
  };
  return (
    <div className="page">
      <ScanReport scan={running} connection="live" version={0} />
      <ScanReport scan={scan} connection="done" version={0} fetchFindings={fetchFindings} />
    </div>
  );
}
