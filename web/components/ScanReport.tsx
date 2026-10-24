import Link from "next/link";
import { dedupSummary, isTerminal, issueSummary, projectName } from "@/lib/format";
import type { Connection } from "@/lib/useScan";
import type { FindingsPage, FindingsQuery, GuidanceApi, ScanView, Severity } from "@/lib/types";
import { SeverityCounts, StatusBadge } from "./Badges";
import { ElapsedTime } from "./ElapsedTime";
import { LocalTime } from "./LocalTime";
import { FindingsTable } from "./FindingsTable";
import { ReportDownloads } from "./ReportDownloads";
import { ToolCards } from "./ToolCards";

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const step = (n: number, max: number) => `w-${Math.max(5, Math.round((n / Math.max(max, 1)) * 20) * 5)}`;

/** Presentational scan view: shared by the live page (useScan) and the dev-only preview. */
export function ScanReport({
  scan,
  connection,
  version,
  fetchFindings,
  crumb = { href: "/app", label: "← All scans" },
  downloads,
  guidance,
}: {
  scan: ScanView;
  connection: Connection;
  version: number;
  fetchFindings?: (id: string, q: FindingsQuery, limit?: number) => Promise<FindingsPage>;
  crumb?: { href: string; label: string };
  guidance?: GuidanceApi;
  downloads?: boolean; // whole-scan PDF/HTML/SARIF downloads; needs the API, so off for the sample scan
}) {
  const done = isTerminal(scan.status);
  const max = Math.max(...ORDER.map((s) => scan.severity_counts[s] ?? 0));
  // Raw, pre-correlation signal only: cross-tool deduplication (core/correlation) needs every tool's
  // output to decide what's a duplicate, so a real, reviewable Finding/Issue doesn't exist in the
  // database until the whole scan finishes (core/pipeline.py persists once, at the very end). This
  // is real progress -- each count is live from that scanner's own report -- just not yet the
  // deduplicated number the finished summary below shows, so it's labelled "raw" rather than implying
  // reviewable results are already here.
  const finishedTools = Object.values(scan.tool_status).filter((t) => t.status !== "skipped");
  const rawSoFar = finishedTools.reduce((n, t) => n + t.findings, 0);
  const stalled = Object.entries(scan.tool_status).filter(([, t]) => t.status === "error" || t.status === "timeout");
  return (
    <>
      <section className="section" aria-labelledby="scan-h">
        <div className="app-head">
          <Link href={crumb.href} className="crumb">{crumb.label}</Link>
          <div className="scan-head">
            <div className="stack">
              <span className="eyebrow">Scan</span>
              <h1 id="scan-h" className="wrap">{projectName(scan.source_label)}</h1>
              {projectName(scan.source_label) !== scan.source_label && <p className="small muted wrap scan-source">{scan.source_label}</p>}
            </div>
            <span className="scan-head-right">
              {!done && (scan.started_at ?? scan.created_at) && <ElapsedTime since={scan.started_at ?? scan.created_at} />}
              <StatusBadge status={scan.status} />
            </span>
          </div>
          <p className="label dimmed" role="status" aria-live="polite">
            {done
              ? <>Finished {scan.finished_at ? <LocalTime iso={scan.finished_at} /> : ""}</>
              : connection === "live" ? "Live: updates arrive as each scanner finishes"
              : connection === "polling" ? "Refreshing every few seconds" : "Connecting"}
          </p>
          {!done && finishedTools.length > 0 && (
            <p className="label dimmed" role="status" aria-live="polite">
              {finishedTools.length} of {scan.tools.length} scanners reported in, {rawSoFar} raw finding{rawSoFar === 1 ? "" : "s"} so
              far. Duplicates across scanners aren&apos;t merged yet -- the real count appears once the scan finishes.
            </p>
          )}
          {downloads && done && scan.status !== "failed" && <ReportDownloads scanId={scan.id} />}
          {scan.error && <p className="error" role="alert">{scan.error}</p>}
          {done && stalled.length > 0 && (
            <p className="warn">
              {stalled.length === 1 && stalled[0]
                ? `${stalled[0][0]} ${stalled[0][1].status === "timeout" ? "timed out" : "failed"}, so its results may be incomplete.`
                : `${stalled.map(([name]) => name).join(", ")} didn't finish, so their results may be incomplete.`}{" "}
              The other scanners finished. <Link href="/app">Start a new scan →</Link>
            </p>
          )}
        </div>
        <ToolCards scan={scan} />
        {done && scan.status !== "failed" && (
          <div className="summary">
            <div>
              <span className="eyebrow plain">Unique findings</span>
              <span className="numeral">{scan.unique_findings}</span>
              <p className="dedup-note">{dedupSummary(scan)}</p>
              {issueSummary(scan.issue_counts) && (
                <p className="dedup-note">{issueSummary(scan.issue_counts)}</p>
              )}
            </div>
            <div>
              <span className="eyebrow plain">By severity</span>
              <div className="sevbars">
                {ORDER.filter((s) => (scan.severity_counts[s] ?? 0) > 0).map((s) => (
                  <div key={s} className={`sevrow sev-${s.toLowerCase()}`}>
                    <span>{s}</span>
                    <span className="track"><i className={step(scan.severity_counts[s] ?? 0, max)} /></span>
                    <span className="n">{scan.severity_counts[s]}</span>
                  </div>
                ))}
                {max === 0 && (
                  <span className="muted small">
                    {finishedTools.filter((t) => t.status === "ok").length} scanner
                    {finishedTools.filter((t) => t.status === "ok").length === 1 ? "" : "s"} found no issues.
                  </span>
                )}
              </div>
            </div>
            <div>
              <span className="eyebrow plain">Summary</span>
              <SeverityCounts counts={scan.severity_counts} />
              {Object.values(scan.tool_status).some((t) => t.raw_artifact === "withheld") && (
                <p className="small muted">Raw scanner output was not stored because secrets were found; it could echo them.</p>
              )}
            </div>
          </div>
        )}
        {Object.entries(scan.tool_status).flatMap(([tool, t]) => (t.warnings ?? []).map((w) => `${tool}: ${w}`)).map((w) => (
          <p key={w} className="warn" role="status">{w}</p>
        ))}
      </section>
      {done && scan.status !== "failed" && <FindingsTable scan={scan} version={version} fetchFindings={fetchFindings} guidance={guidance} />}
    </>
  );
}
