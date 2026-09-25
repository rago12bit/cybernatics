"use client";

import Link from "next/link";
import { APP_HREF, DEMO_ONLY } from "@/lib/site";
import { ScanReport } from "@/components/ScanReport";
import { PAGE_SIZE, severityRank } from "@/lib/format";
import type { Finding, FindingsPage, FindingsQuery, GuidanceApi, Remediation, ScanView } from "@/lib/types";
import data from "@/lib/demo-data.json";
import guidanceData from "@/lib/demo-guidance.json";

// A real scan of the small test fixture (Bandit + Semgrep + Gitleaks + Trivy + OSV-Scanner), captured once.
// Lets anyone explore the full report UI without an API token. No network calls are made.
const scan = data.scan as unknown as ScanView;
const all = data.findings as unknown as Finding[];

// Mirrors the API's filtering, sorting and paging so the table behaves exactly like the real thing.
async function fetchFindings(_id: string, q: FindingsQuery, limit: number = PAGE_SIZE): Promise<FindingsPage> {
  let rows = all.filter(
    (f) =>
      (q.severity.length === 0 || q.severity.includes(f.scoring.normalized_severity)) &&
      (!q.category || f.taxonomy.category === q.category) &&
      (!q.tool || f.evidence.reported_by.includes(q.tool)) &&
      (!q.path.trim() || f.location.path.includes(q.path.trim())),
  );
  const risk = (f: Finding) => f.scoring.risk_score ?? -1;
  rows = [...rows].sort((a, b) =>
    q.sort === "path"
      ? a.location.path.localeCompare(b.location.path) || a.location.start_line - b.location.start_line
      : q.sort === "risk"
        ? risk(b) - risk(a) || a.location.path.localeCompare(b.location.path)
        : severityRank(b.scoring.normalized_severity) - severityRank(a.scoring.normalized_severity) ||
          risk(b) - risk(a) ||
          a.location.path.localeCompare(b.location.path),
  );
  return { total: rows.length, limit, offset: q.page * limit, items: rows.slice(q.page * limit, (q.page + 1) * limit) };
}

// The sample site has no API. Guidance was precomputed by the real retrieval code (scripts/gen-demo-guidance.py);
// it contains reference text only, and AI suggestions are off, because this site runs no model.
const staticGuidance = guidanceData as unknown as Record<string, Remediation>;
const demoGuidance: GuidanceApi = {
  get: async (_scanId, findingId) => {
    const r = staticGuidance[findingId];
    if (!r) throw new Error("No guidance for this finding in the sample.");
    return { finding_id: findingId, static: r, ai: null, ai_enabled: false, model: null };
  },
  request: async () => {
    throw new Error("AI suggestions are not available in the sample.");
  },
};

export function DemoReport() {
  return (
    <div className="page">
      <div className="demo-banner">
        <div>
          <span className="eyebrow plain">Sample data</span>
          <p className="small muted">A real scan of a small test project, so you can explore the report without an API token.</p>
        </div>
        <Link href={APP_HREF} className="btn primary sm">{DEMO_ONLY ? "Run it yourself →" : "Scan your own →"}</Link>
      </div>
      <ScanReport scan={scan} connection="done" version={0} fetchFindings={fetchFindings} guidance={demoGuidance} crumb={{ href: "/about", label: "← About Bulwark" }} />
    </div>
  );
}
