import type { Finding, FindingsQuery, ScanView, Severity } from "./types";
import { FILTER_TOOLS, SEVERITIES } from "./types";

export const PAGE_SIZE = 50;

export function severityRank(s: Severity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(s);
}

export function defaultQuery(): FindingsQuery {
  return { severity: [], category: "", tool: "", path: "", sort: "severity", page: 0 };
}

/** Build the API query string. Empty filters are omitted; values are URL-encoded. */
export function findingsQueryString(q: FindingsQuery, limit: number = PAGE_SIZE): string {
  const p = new URLSearchParams();
  for (const s of q.severity) p.append("severity", s);
  if (q.category) p.set("category", q.category);
  if (q.tool) p.set("tool", q.tool);
  if (q.path.trim()) p.set("path", q.path.trim());
  p.set("sort", q.sort);
  p.set("limit", String(limit));
  p.set("offset", String(q.page * limit));
  return p.toString();
}

export function pageCount(total: number): number {
  return Math.max(1, Math.ceil(total / PAGE_SIZE));
}

// Which scanners could even have found each kind of issue. "2 of 5" would understate agreement:
// Trivy cannot find a SQL injection, so it is not a scanner that "missed" one.
const CATEGORY_TOOLS: Record<string, string[]> = {
  sast: ["bandit", "semgrep", "gosec"],
  sca: ["trivy", "osv-scanner", "grype"],
  secrets: ["gitleaks"],
  iac: ["trivy", "checkov"],
  container: ["trivy", "dockle"],
};
const CATEGORY_NOUN: Record<string, string> = {
  sast: "code scanners", sca: "dependency scanners", secrets: "secret scanners", iac: "scanners", container: "scanners",
};

/** "Flagged by 2 of 2 code scanners": the denominator is scanners that ran AND cover this category. */
export function agreementLabel(f: Finding, scan: ScanView | null): string {
  const n = f.evidence.agreement_count;
  if (!scan) return `Flagged by ${n} scanner${n === 1 ? "" : "s"}`;
  const covering = new Set([...(CATEGORY_TOOLS[f.taxonomy.category] ?? []), ...f.evidence.reported_by]);
  const ran = [...covering].filter((t) => scan.tool_status[t] && scan.tool_status[t]!.status === "ok").length;
  const noun = CATEGORY_NOUN[f.taxonomy.category] ?? "scanners";
  return ran >= n && ran > 0 ? `Flagged by ${n} of ${ran} ${noun}` : `Flagged by ${n} scanner${n === 1 ? "" : "s"}`;
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

// ---- Filter state <-> URL (so a filtered view survives refresh and can be shared) ----------------

const SORTS = ["severity", "path", "risk"] as const;

export function isDefaultQuery(q: FindingsQuery): boolean {
  const d = defaultQuery();
  return q.severity.length === 0 && q.category === d.category && q.tool === d.tool && q.path.trim() === "" && q.sort === d.sort;
}

/** Serialise only what differs from the defaults, e.g. `?sev=HIGH,CRITICAL&cat=sca&p=2`. */
export function queryToSearch(q: FindingsQuery): string {
  const p = new URLSearchParams();
  if (q.severity.length) p.set("sev", q.severity.join(","));
  if (q.category) p.set("cat", q.category);
  if (q.tool) p.set("tool", q.tool);
  if (q.path.trim()) p.set("q", q.path.trim());
  if (q.sort !== "severity") p.set("sort", q.sort);
  if (q.page > 0) p.set("p", String(q.page + 1));
  const s = p.toString();
  return s ? `?${s}` : "";
}

/** Parse untrusted URL input back into a valid query: anything unrecognised is dropped, never trusted. */
export function searchToQuery(search: string): FindingsQuery {
  const p = new URLSearchParams(search);
  const q = defaultQuery();
  q.severity = (p.get("sev") ?? "").split(",").filter((s): s is Severity => (SEVERITIES as string[]).includes(s));
  q.severity = [...new Set(q.severity)];
  const cat = p.get("cat") ?? "";
  q.category = ["sast", "sca", "secrets", "iac", "container"].includes(cat) ? cat : "";
  const tool = p.get("tool") ?? "";
  q.tool = (FILTER_TOOLS as readonly string[]).includes(tool) ? tool : "";
  q.path = (p.get("q") ?? "").slice(0, 200);
  const sort = p.get("sort") as (typeof SORTS)[number] | null;
  q.sort = sort && SORTS.includes(sort) ? sort : "severity";
  const page = Number.parseInt(p.get("p") ?? "1", 10);
  q.page = Number.isFinite(page) && page > 1 ? Math.min(page - 1, 10_000) : 0;
  return q;
}

/** "Showing 51-100 of 291" */
export function rangeLabel(total: number, page: number, shown: number): string {
  if (total === 0 || shown === 0) return "No results";
  const from = page * PAGE_SIZE + 1;
  return `Showing ${from}-${from + shown - 1} of ${total}`;
}

/** "just now", "3 min ago", "2 h ago", "4 d ago", else a date. */
export function relativeTime(iso: string, now: number = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  if (s < 7 * 86400) return `${Math.round(s / 86400)} d ago`;
  return new Date(t).toLocaleDateString();
}
