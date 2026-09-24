import type { Finding, FindingsQuery, ScanView, Severity } from "./types";
import { SEVERITIES } from "./types";

export const PAGE_SIZE = 50;

export function severityRank(s: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(s);
}

export function defaultQuery(): FindingsQuery {
  return { severity: [], category: "", tool: "", path: "", sort: "severity", page: 0 };
}

/** Build the API query string. Empty filters are omitted; values are URL-encoded. */
export function findingsQueryString(q: FindingsQuery): string {
  const p = new URLSearchParams();
  for (const s of q.severity) p.append("severity", s);
  if (q.category) p.set("category", q.category);
  if (q.tool) p.set("tool", q.tool);
  if (q.path.trim()) p.set("path", q.path.trim());
  p.set("sort", q.sort);
  p.set("limit", String(PAGE_SIZE));
  p.set("offset", String(q.page * PAGE_SIZE));
  return p.toString();
}

export function pageCount(total: number): number {
  return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

/** "Flagged by 2 of 5 scanners": the denominator is tools that actually ran on this repo. */
export function agreementLabel(f: Finding, scan: ScanView | null): string {
  const ran = scan
    ? Object.values(scan.tool_status).filter((t) => t.status !== "skipped").length
    : 0;
  const n = f.evidence.agreement_count;
  return ran > 0 && ran >= n ? `Flagged by ${n} of ${ran} scanners` : `Flagged by ${n} scanner${n === 1 ? "" : "s"}`;
}

export function dedupSummary(scan: ScanView): string {
  if (scan.raw_findings === 0) return "No findings reported by any scanner.";
  const removed = scan.raw_findings - scan.unique_findings;
  if (removed <= 0) return `${scan.unique_findings} findings (no duplicates across scanners).`;
  return `${scan.raw_findings} raw findings became ${scan.unique_findings} after merging duplicates across scanners (${Math.round(scan.dedup_rate * 100)}% fewer).`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return "";
  return seconds < 1 ? "<1s" : seconds < 60 ? `${Math.round(seconds)}s` : `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

export function locationLabel(f: Finding): string {
  const { path, start_line: a, end_line: b } = f.location;
  return b > a ? `${path}:${a}-${b}` : `${path}:${a}`;
}

export function nativeSeverities(f: Finding): string {
  return Object.entries(f.scoring.native_severity)
    .filter(([, v]) => v !== "")
    .map(([tool, v]) => `${tool}: ${v}`)
    .join(" · ");
}

export function isTerminal(status: string): boolean {
  return status === "completed" || status === "partial" || status === "failed";
}
