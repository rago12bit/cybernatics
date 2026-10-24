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

/** "3 new, 1 reintroduced since the last scan of this project", or null when there's nothing worth
 * saying — no tracked history yet, or every issue is just steady-state "open" (ADR-0012). */
export function issueSummary(counts: ScanView["issue_counts"]): string | null {
  const n = counts?.new ?? 0;
  const r = counts?.reintroduced ?? 0;
  if (n === 0 && r === 0) return null;
  const parts = [n > 0 && `${n} new`, r > 0 && `${r} reintroduced`].filter(Boolean);
  return `${parts.join(", ")} since the last scan of this project.`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return "";
  return seconds < 1 ? "<1s" : seconds < 60 ? `${Math.round(seconds)}s` : `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

export function locationLabel(f: Finding): string {
  const { path, start_line: a, end_line: b, route, host } = f.location;
  if (!path && route) return `${host ?? ""}${route}`; // a web finding: where it was reached, not a file
  return b > a ? `${path}:${a}-${b}` : `${path}:${a}`;
}

// One line, no range: the Issues list and the project overview.
export function shortLocation(f: Finding): string {
  const { path, start_line, route, host } = f.location;
  return !path && route ? `${host ?? ""}${route}` : `${path}:${start_line}`;
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
  return formatDate(t);
}

// One way to write a date across the app: the viewer's own locale, month as a word so 10/11 can't be
// misread, and never seconds. Calendar grids and pickers keep their own layouts.
const DAY: Intl.DateTimeFormatOptions = { day: "numeric", month: "short", year: "numeric" };
const DAY_TIME: Intl.DateTimeFormatOptions = { ...DAY, hour: "numeric", minute: "2-digit" };

/** "Oct 11, 2026" (in the viewer's locale), or "—" for a missing or broken timestamp. */
export function formatDate(when: string | number | Date): string {
  const d = new Date(when);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString(undefined, DAY);
}

/** "Oct 11, 2026, 6:52 PM" (in the viewer's locale), or "—" for a missing or broken timestamp. */
export function formatDateTime(when: string | number | Date): string {
  const d = new Date(when);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(undefined, DAY_TIME);
}

// The hosts a project can be cloned from (core/gitfetch.py); a repository there is named `owner/repo`.
const CODE_HOSTS = new Set(["github.com", "gitlab.com", "bitbucket.org"]);
const URLISH = /^(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?)(\/[^\s?#]*)?$/i;

/**
 * A project the way people say it: `acme/payments-api` for a repository on a code host, the host and
 * path for a web target (`shop.example.com`), and anything else -- an uploaded archive, an import --
 * unchanged. Screens that shorten a label keep the full one as a tooltip.
 */
export function projectName(label: string): string {
  const m = URLISH.exec(label.trim());
  if (!m) return label;
  const host = m[1]!.toLowerCase();
  const path = (m[2] ?? "").replace(/\/+$/, "");
  if (CODE_HOSTS.has(host) && path.split("/").filter(Boolean).length >= 2) return path.slice(1).replace(/\.git$/i, "");
  return /^https?:\/\//i.test(label.trim()) ? host + path : label;
}

/** The code host a project lives on ("github.com"), or null for web targets, uploads and imports. */
export function projectHost(label: string): string | null {
  const m = URLISH.exec(label.trim());
  const host = m?.[1]?.toLowerCase();
  return host && CODE_HOSTS.has(host) && (m?.[2] ?? "").split("/").filter(Boolean).length >= 2 ? host : null;
}

/** A date as the person's own calendar day, "2026-10-08" -- for a date a person picks (an
 * engagement's start, an acceptance's expiry). Not `toISOString()`, which is the UTC day: east of
 * UTC, just after midnight, that is still yesterday (found in Week 74). */
export function localDay(d: Date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}
