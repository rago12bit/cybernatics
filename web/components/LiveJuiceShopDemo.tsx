"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { APP_HREF, DEMO_ONLY } from "@/lib/site";
import { ScanReport } from "@/components/ScanReport";
import { PAGE_SIZE, severityRank } from "@/lib/format";
import type { Finding, FindingsPage, FindingsQuery, ScanView, ToolStatus } from "@/lib/types";
import data from "@/lib/juiceshop-demo-data.json";

// A real scan of the real, public OWASP Juice Shop (github.com/juice-shop/juice-shop), captured
// once by Bulwark's own five scanners -- see scripts/gen-juiceshop-demo-data.py for exactly how.
// Every finding, every tool's duration, and the final severity counts below are what Bulwark
// actually reported; nothing here is written or tuned by hand for a better-looking demo.
const finalScan = data.scan as unknown as ScanView;
const allFindings = data.findings as unknown as Finding[];

// Reveal tools in the order they really finished (fastest first), proportional to their real
// durations -- compressed into a few seconds so a visitor isn't staring at a loading screen for
// the real ~20 seconds Semgrep took, but the ORDER, and every number shown once a tool "finishes",
// are exactly what really happened.
const REPLAY_MS = 6000;
const realTools = Object.entries(finalScan.tool_status)
  .filter(([, t]) => t.status !== "skipped")
  .sort((a, b) => (a[1].duration_seconds ?? 0) - (b[1].duration_seconds ?? 0));
const maxRealSeconds = Math.max(...realTools.map(([, t]) => t.duration_seconds ?? 0), 1);
const skippedTools = Object.fromEntries(
  Object.entries(finalScan.tool_status).filter(([, t]) => t.status === "skipped"),
);

async function fetchFindings(_id: string, q: FindingsQuery, limit: number = PAGE_SIZE): Promise<FindingsPage> {
  let rows = allFindings.filter(
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

export function LiveJuiceShopDemo() {
  const [elapsed, setElapsed] = useState(0);
  const [runId, setRunId] = useState(0); // bumped to replay from the start
  // ElapsedTime (in ScanReport's header) counts up from `started_at` against the real clock, so a
  // page loaded hours after this JSON was generated must not show the generation timestamp -- it
  // needs *this* replay's own start time, refreshed every time the replay restarts.
  const [startedAt, setStartedAt] = useState(() => new Date().toISOString());
  const done = elapsed >= REPLAY_MS;

  useEffect(() => {
    setElapsed(0);
    setStartedAt(new Date().toISOString());
    const start = Date.now();
    const id = setInterval(() => {
      const now = Date.now() - start;
      setElapsed(now >= REPLAY_MS ? REPLAY_MS : now);
    }, 100);
    return () => clearInterval(id);
  }, [runId]);

  const scan: ScanView = useMemo(() => {
    if (done) {
      const finishedAt = new Date(Date.parse(startedAt) + REPLAY_MS).toISOString();
      return { ...finalScan, created_at: startedAt, started_at: startedAt, finished_at: finishedAt };
    }
    const tool_status: Record<string, ToolStatus> = { ...skippedTools };
    for (const [name, t] of realTools) {
      const revealAt = ((t.duration_seconds ?? 0) / maxRealSeconds) * REPLAY_MS;
      if (elapsed >= revealAt) tool_status[name] = t;
    }
    return { ...finalScan, status: "running", created_at: startedAt, started_at: startedAt, finished_at: null, tool_status };
  }, [done, elapsed, startedAt]);

  return (
    <div className="page">
      <div className="demo-banner">
        <div>
          <span className="eyebrow plain">Live demo</span>
          <p className="small muted">
            A real scan of the real, public <a href="https://github.com/juice-shop/juice-shop">OWASP Juice Shop</a> --
            {done ? " replay finished; rerun it below." : " replaying how it happened, fastest scanner first."}{" "}
            Prefer a smaller example? <Link href="/sample">See a 5-tool sample scan →</Link>
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          {done && (
            <button type="button" className="btn sm" onClick={() => setRunId((n) => n + 1)}>
              ↻ Watch it again
            </button>
          )}
          <Link href={APP_HREF} className="btn primary sm">{DEMO_ONLY ? "Run it yourself →" : "Scan your own →"}</Link>
        </div>
      </div>
      <ScanReport
        scan={scan}
        connection={done ? "done" : "live"}
        version={runId}
        fetchFindings={fetchFindings}
        crumb={{ href: "/", label: "← Home" }}
      />
    </div>
  );
}
