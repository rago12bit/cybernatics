// Mirrors the Bulwark API schemas (docs/openapi.json). Anything a scanned repository can influence
// (titles, snippets, paths, URLs) is untrusted and must only ever be rendered as text.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScanStatus = "queued" | "running" | "completed" | "partial" | "failed";
export type ToolState = "ok" | "timeout" | "error" | "skipped";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const CATEGORIES = ["sast", "sca", "secrets", "iac", "container"] as const;
export const TOOLS = ["bandit", "semgrep", "gitleaks", "trivy", "osv-scanner"] as const;
// Tier 2: available but off by default (heavier images). Dockle needs a built image: CLI `scan-image` only.
export const OPTIONAL_TOOLS = ["grype", "checkov", "gosec"] as const;
export const FILTER_TOOLS = [...TOOLS, ...OPTIONAL_TOOLS, "dockle"] as const;
export const TERMINAL: ScanStatus[] = ["completed", "partial", "failed"];

export interface ToolStatus {
  status: ToolState;
  findings: number;
  exit_code: number | null;
  duration_seconds: number | null;
  error: string | null;
  warnings?: string[]; // finished, but possibly incomplete
  raw_artifact: "available" | "withheld" | null;
}

export interface ScanView {
  id: string;
  status: ScanStatus;
  source_type: string;
  source_label: string;
  tools: string[];
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  tool_status: Record<string, ToolStatus>;
  severity_counts: Partial<Record<Severity, number>>;
  raw_findings: number;
  unique_findings: number;
  dedup_rate: number;
  /** Findings by Issue lifecycle state (ADR-0012): "new" here for the first time, "open" seen
   * before, "reintroduced" after having been fixed. Empty for scans that aren't "completed", or
   * from before this tracking existed. */
  issue_counts?: Partial<Record<"new" | "open" | "reintroduced", number>>;
}

export type TriageStatus = "open" | "not_a_risk" | "accepted";

/** Which side of an Issue's lifecycle a finding is on right now (ADR-0012). Absent ("null") means
 * this scan predates Issue tracking, or has no asset. A "fixed" issue never appears here — it has
 * no occurrence in the scan that would carry this field. Triage (plan §28.3) is a human decision
 * layered on top of `state`, not a replacement for it. */
export interface IssueRef {
  id: string;
  state: "new" | "open" | "reintroduced";
  triage_status?: TriageStatus;
  triage_reason?: string | null;
  triage_expires_at?: string | null;
  first_seen_at?: string | null;
}

export interface IssueHistoryEvent {
  at: string;
  label: string;
}

export interface BulkTriageResult {
  updated: string[];
  failed: { issue_id: string; error: string }[];
}

/** Guidance for one finding. `source` says whether a model wrote it; `label` is always displayed with it. */
export interface Remediation {
  source: "ai" | "static";
  label: string;
  explanation: string;
  impact: string;
  fix_summary: string;
  suggested_patch: string | null; // a unified diff, shown as text: Bulwark never applies it
  confidence: string; // confidence in the fix, not in whether the finding is real
  model: string | null;
  degraded_reason: string | null;
  warnings: string[];
  patch_status: "verified" | "unverified" | null; // was the patch checked against the code it fixes?
  references: { title: string; url: string }[];
  from_cache: boolean;
  generated_at: string | null;
}

export interface Guidance {
  finding_id: string;
  static: Remediation;
  ai: Remediation | null;
  ai_enabled: boolean;
  model: string | null;
}

export interface GuidanceApi {
  get(scanId: string, findingId: string): Promise<Guidance>;
  request(scanId: string, findingId: string): Promise<Remediation>;
}

export interface ScanSummary {
  id: string;
  status: ScanStatus;
  source_type: string;
  source_label: string;
  created_at: string;
  finished_at: string | null;
  unique_findings: number;
  severity_counts: Partial<Record<Severity, number>>;
}

export interface ComparedIssue {
  id: string;
  title: string;
  severity: string;
  category: string;
  path: string;
}

export interface ScanComparisonSide {
  scan_id: string;
  source_label: string;
  finished_at: string | null;
  github_pr_number: number | null;
}

/** Plan §28.6's scan comparison screen. */
export interface ScanComparison {
  earlier: ScanComparisonSide;
  later: ScanComparisonSide;
  new: ComparedIssue[];
  fixed: ComparedIssue[];
  reintroduced: ComparedIssue[];
  unchanged: ComparedIssue[];
}

export interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  location: { path: string; start_line: number; end_line: number; snippet: string };
  taxonomy: {
    category: string;
    cwe: string[];
    owasp_top_10_2021: string[];
    cve: string[];
    aliases: string[];
  };
  scoring: {
    native_severity: Record<string, string>;
    normalized_severity: Severity;
    cvss_v3_1: number | null;
    risk_score: number | null;
    epss_score?: number | null; // chance of exploitation in 30 days (FIRST.org EPSS)
    in_cisa_kev?: boolean; // known exploited in the wild (CISA KEV)
    risk_factors?: string[]; // human-readable reasons behind risk_score
    reachable?: boolean | null; // false only when something positively ruled it out; unknown otherwise
    confidence: number;
  };
  evidence: {
    reported_by: string[];
    agreement_count: number;
    rule_ids: Record<string, string[]>;
  };
  remediation: { summary: string; references: string[]; generated_by: string };
  package: { name: string; version: string; ecosystem: string } | null;
  /** A concrete source-to-sink path (plan §20.3/§28.3), empty when taint analysis found none for
   * this finding -- absence here means "no confirmed path found," never "confirmed unreachable." */
  taint_path: { path: string; line: number; description: string; is_sink: boolean; snippet: string }[];
  issue?: IssueRef | null;
  /** Only present on /assets/.../issues responses (Week 34): the scan this occurrence came from,
   * so the issue detail screen can reuse the existing scan-scoped guidance API without a second
   * round trip to look it up. */
  scan_id?: string;
}

export interface FindingsPage {
  total: number;
  limit: number;
  offset: number;
  items: Finding[];
}

export interface FindingsQuery {
  severity: Severity[];
  category: string;
  tool: string;
  path: string;
  sort: "severity" | "path" | "risk";
  page: number; // zero-based
}

/** A project (plan §27): one distinct repository, most recently scanned first. */
export interface AssetSummary {
  id: string;
  label: string;
  source_type: string;
  last_scanned_at: string;
  latest_scan_id: string | null;
  latest_scan_status: ScanStatus | null;
  open_issue_count: number;
}

export interface ScannedTool {
  tool: string;
  status: ToolState;
  findings: number;
}

export interface TrendPoint {
  scan_id: string;
  finished_at: string;
  open_count: number;
}

/** Plan §28.1's project overview screen -- see api/schemas.py's ProjectOverview for how the server
 * derives each field from existing scan/issue data (nothing here is a new source of truth). */
export interface ProjectOverview {
  asset: AssetSummary;
  verdict_count: number;
  fix_first: Finding[];
  more_at_lower_risk: number;
  since_previous_scan: { fixed: number; new: number; returned: number };
  trend: TrendPoint[];
  scanned: ScannedTool[];
  latest_scan_id: string | null;
  latest_scan_finished_at: string | null;
}

export type ProgressEvent =
  | ({ type: "snapshot" } & ScanView) // the server's full view when the socket connects
  | { type: "scan.started"; tools: string[] }
  | ({ type: "tool.finished"; tool: string } & Partial<ToolStatus>)
  | { type: "scan.finished"; status: ScanStatus; findings?: number; error?: string };
