"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { APP_HREF, DEMO_ONLY } from "@/lib/site";
import { ScanReport } from "@/components/ScanReport";
import { PAGE_SIZE, severityRank } from "@/lib/format";
import { codeFindings, codeScan, provenance, runtimeFindings, runtimeScan } from "@/lib/recording";
import type { Finding, FindingsPage, FindingsQuery, ScanView, ToolStatus } from "@/lib/types";
import "./site/site-pages.css";

// A real scan of one release of the public OWASP Juice Shop, recorded by
// scripts/record-juiceshop.py: its source by the default scanners, and its running container by a
// passive DAST campaign's tools. Every finding, every tool's duration, and the severity counts are
// what Bulwark actually reported; nothing here is written or tuned by hand.
const finalScan = codeScan;

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

function pageOf(allFindings: Finding[], q: FindingsQuery, limit: number): FindingsPage {
  let rows = allFindings.filter(
    (f) =>
      (q.severity.length === 0 || q.severity.includes(f.scoring.normalized_severity)) &&
      (!q.category || f.taxonomy.category === q.category) &&
      (!q.tool || f.evidence.reported_by.includes(q.tool)) &&
      (!q.path.trim() || (f.location.path || f.location.route || "").includes(q.path.trim())),
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

async function fetchCode(_id: string, q: FindingsQuery, limit: number = PAGE_SIZE): Promise<FindingsPage> {
  return pageOf(codeFindings, q, limit);
}
async function fetchRuntime(_id: string, q: FindingsQuery, limit: number = PAGE_SIZE): Promise<FindingsPage> {
  return pageOf(runtimeFindings, q, limit);
}

export function LiveJuiceShopDemo() {
  const [half, setHalf] = useState<"code" | "runtime">("code");
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

  const code = half === "code";
  return (
    <div className="page">
      <div className="demo-banner">
        <div>
          <span className="eyebrow plain">Recorded scan</span>
          <p className="small muted">
            A real scan of the public <a href="https://github.com/juice-shop/juice-shop">OWASP Juice Shop</a>{" "}
            {provenance.version}, recorded {provenance.recorded_on} --
            {code
              ? done ? " replay finished; rerun it below." : " replaying how it happened, fastest scanner first."
              : " the running container, scanned by a passive web campaign (ZAP baseline)."}
          </p>
        </div>
        <div className="demo-actions">
          {code && done && (
            <button type="button" className="btn sm" onClick={() => setRunId((n) => n + 1)}>
              ↻ Watch it again
            </button>
          )}
          <Link href={APP_HREF} className="btn primary sm">{DEMO_ONLY ? "Run it yourself →" : "Scan your own →"}</Link>
        </div>
      </div>
      <div className="demo-switch">
        <span className="label dimmed" id="half-label">Show</span>
        <div className="seg" role="group" aria-labelledby="half-label">
          <button type="button" aria-pressed={code} onClick={() => setHalf("code")}>The code · {codeScan.unique_findings}</button>
          <button type="button" aria-pressed={!code} onClick={() => setHalf("runtime")}>The running app · {runtimeScan.unique_findings}</button>
        </div>
        <Link href="/#recording" className="small muted">What this recording does not show</Link>
      </div>
      {code ? (
        <ScanReport
          key="code"
          scan={scan}
          connection={done ? "done" : "live"}
          version={runId}
          fetchFindings={fetchCode}
          crumb={{ href: "/", label: "← Home" }}
        />
      ) : (
        <ScanReport
          key="runtime"
          scan={runtimeScan}
          connection="done"
          version={0}
          fetchFindings={fetchRuntime}
          crumb={{ href: "/", label: "← Home" }}
        />
      )}
    </div>
  );
}
