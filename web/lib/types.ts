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
  /** Set once a DAST campaign's own finding matched this Issue on the same route+CWE (plan §22.4,
   * Week 49 task 4) -- a static finding a real HTTP request actually reached. */
  confirmed_at_runtime_at?: string | null;
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

/** Plan §23's cost-per-scan dashboard (Week 50) -- an estimate, not a bill; see
 * core/observability/cost.py's own docstring for what it does and doesn't account for. */
export interface ScanCost {
  scan_id: string;
  compute_seconds: number;
  compute_usd: number;
  llm_tokens: number;
  llm_usd: number;
  total_usd: number;
}

export interface CostSummaryRow {
  scan_id: string;
  source_label: string;
  created_at: string;
  compute_seconds: number;
  llm_tokens: number;
  total_usd: number;
}

export interface CostSummary {
  days: number;
  scan_count: number;
  total_compute_seconds: number;
  total_llm_tokens: number;
  total_compute_usd: number;
  total_llm_usd: number;
  total_usd: number;
  scans: CostSummaryRow[];
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

export type DependencyRelation = "direct" | "transitive" | "root" | "unknown";

export interface DependencyScorecard {
  score: number;
  checks: Record<string, number>;
  date: string;
}

/** One SBOM package (plan §20.5) -- `purl` is this package's own stable identity; `depends_on`
 * lists the purls it depends on, which is all the Dependencies screen needs to walk the graph
 * (root to any package) client-side, the same way `core.supplychain.dependency_view.path_to` does
 * server-side. */
export interface DependencyPackage {
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  license: string;
  path: string;
  relation: DependencyRelation;
  depends_on: string[];
  scorecard: DependencyScorecard | null;
}

/** Plan §20.5's Dependencies screen: `scan_id`/`components` are 0/empty (not missing) when no
 * scan has opted "syft" into its tools yet -- see api/schemas.py's DependenciesView. */
export interface DependenciesView {
  scan_id: string | null;
  generated_at: string | null;
  components: number;
  ecosystems: Record<string, number>;
  packages: DependencyPackage[];
}

export type ProgressEvent =
  | ({ type: "snapshot" } & ScanView) // the server's full view when the socket connects
  | { type: "scan.started"; tools: string[] }
  | ({ type: "tool.finished"; tool: string } & Partial<ToolStatus>)
  | { type: "scan.finished"; status: ScanStatus; findings?: number; error?: string };

/** The verified-fix agent (plan §21.2, §28.4). `status` is one of Temporal's own terminal/
 * non-terminal states, mirrored onto the DB row `core.fixagent.store` writes. */
export type VerifiedFixStatus =
  | "running"
  | "awaiting_approval"
  | "approved"
  | "rejected"
  | "opened_pr"
  | "failed"
  | "inconclusive";

export interface VerifiedFixPatch {
  explanation: string;
  patch: string;
  confidence: "high" | "medium" | "low";
  tokens_used: number;
}

export interface VerifiedFixStep {
  name: "rerun_rule" | "rerun_scanners" | "run_tests";
  passed: boolean;
  detail: string;
}

export interface VerifiedFixAttempt {
  attempt: number;
  steps: VerifiedFixStep[];
  feedback?: string;
}

export interface VerifiedFixView {
  run_id: string;
  issue_id: string;
  status: VerifiedFixStatus;
  attempts: number;
  latest_patch: VerifiedFixPatch | null;
  verification_record: VerifiedFixAttempt[];
  ended_reason:
    | "overall_timeout"
    | "per_attempt_timeout"
    | "max_attempts_exhausted"
    | "approval_timeout"
    | null;
  pr_url: string | null;
  created_at: string;
  updated_at: string;
}

export interface VerifiedFixStarted {
  run_id: string;
  workflow_id: string;
}

/** The triage assistant's verdict on one Issue (plan §21.3) -- advisory only, distinct from
 * `IssueRef.triage_status` (a human decision). `null` until someone asks for one. */
export interface TriageAssistantView {
  verdict: "likely_real" | "likely_false_positive" | "unsure";
  confidence: "high" | "medium" | "low";
  rationale: string;
  supporting_lines: number[];
  model: string;
  generated_at: string;
}

/** One Hypotheses-lane candidate (plan §21.4) -- off by default, its own tab, excluded from the
 * risk score until a person promotes it. */
export interface Hypothesis {
  id: string;
  route_method: string;
  route_path: string;
  file: string;
  line: number;
  evidence: string;
  suggested_check: string;
  confidence: "high" | "medium" | "low";
  model: string;
  status: "open" | "promoted" | "dismissed";
  promoted_issue_id: string | null;
  created_at: string;
}

export interface GenerateHypothesesResult {
  generated: number;
  hypotheses: Hypothesis[];
}

/** The security copilot (plan §21.5): tool-grounded chat about one project, every answer cited
 * against real issues/code -- never shown until the citation checks out. */
export interface Citation {
  kind: "issue" | "code";
  issue_id: string | null;
  path: string | null;
  line: number | null;
}

export interface CopilotMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  citations: Citation[] | null;
  created_at: string;
}

export interface CopilotConversation {
  id: string;
  asset_id: string;
  context_kind: "issue" | "scan" | null;
  context_id: string | null;
  created_at: string;
  last_message_at: string;
}

/** An attack path (plan §21.6, §28.5): a chain from an entry point through the project's own open
 * issues to real impact, computed deterministically -- the narrative is a best-effort description
 * of it, never the source of the chain itself. */
export interface AttackPathNode {
  id: string;
  kind: "entrypoint" | "issue" | "secret" | "cloud_resource";
  label: string;
  issue_id: string | null;
  detail: string;
}

export interface AttackPathEdge {
  kind: "reachable_from" | "grants_access_to" | "exposes";
  source: string;
  target: string;
  rule_id: string;
}

export interface AttackPath {
  id: string;
  likelihood: "low" | "medium" | "high";
  impact: "low" | "medium" | "high" | "critical";
  rank_score: number;
  cheapest_link: string;
  narrative: string | null;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
}

/** A project's threat-model draft (plan §21.7): a Mermaid data-flow diagram plus a STRIDE table,
 * generated from code intelligence -- a starting point for a person's own review, editable and
 * stored, never silently overwritten except by an explicit regenerate. */
export interface StrideRow {
  element: string;
  element_kind: "external_entity" | "process" | "data_store" | "external_interactor";
  category: string;
  prompt: string;
}

export interface ThreatModel {
  asset_id: string;
  mermaid: string;
  stride: StrideRow[];
  version: number;
  source: "generated" | "edited";
  updated_at: string;
  updated_by: string | null;
}

/** How long this organization keeps a scan's encrypted artifacts before crypto-shredding them
 * (plan §22.2) -- always has a value, the plan's own default (7 days) when never set explicitly. */
export interface RetentionSettings {
  org_id: string;
  retention_days: number;
}

/** Proof that whoever registered a web/DAST target actually controls it (plan §22.4) -- required
 * before any campaign can run against it (Week 49 task 3). */
export interface AssetVerification {
  asset_id: string;
  domain: string;
  method: "dns_txt" | "well_known";
  status: "pending" | "verified" | "failed";
  record_name: string | null;
  record_value: string | null;
  well_known_url: string | null;
  file_content: string | null;
  created_at: string;
  verified_at: string | null;
  last_checked_at: string | null;
  last_error: string | null;
}

// --- Importing reports (Week 54, plan §42.1, ADR-0040) -------------------------------------------

export type ImportCounts = {
  new: number;
  unchanged: number;
  reopened: number;
  closed: number;
  /** Issues the file stopped listing that stay open because another source still reports them. */
  detached: number;
};

export type ImportStatus =
  | "queued" | "processing" | "previewed" | "applied" | "duplicate" | "failed" | "cancelled" | "reverted";

export type ImportCreated = {
  import_id: string;
  status: ImportStatus;
  parser: string;
  /** How sure format detection was; null when the caller named the parser. */
  confidence: number | null;
  test_id: string;
  duplicate: boolean;
};

export type ImportView = {
  id: string;
  status: ImportStatus;
  mode: "apply" | "preview";
  parser: string;
  file_name: string | null;
  test_id: string;
  engagement_id: string | null;
  counts: ImportCounts | null;
  reopened_issue_ids: string[];
  closed_issue_ids: string[];
  detached_issue_ids: string[];
  ids_truncated: boolean;
  warnings: string[];
  error: string | null;
  close_missing: boolean;
  scope: "test" | "engagement";
  dedup_complete: boolean;
  created_at: string;
  reverted_at: string | null;
};

export type ParserInfo = {
  name: string;
  label: string;
  formats: string[];
  categories: string[];
  recommended_dedup?: string;
};

// --- Matching: deduplication per source (Week 58, plan §42.3, ADR-0042) ------------------------------

export type DedupStrategyName = "fingerprint_v2" | "tool_id" | "hash_fields" | "tool_id_or_hash" | "package";
export type DedupSource = {
  source: string;
  strategy: DedupStrategyName;
  fields: string[];
  version: number;
  recommended: DedupStrategyName | null;
  issues_seen: number;
  changed_at: string | null;
  changed_by: string | null;
  effect: Record<string, number | string>;
};
export type DedupOverview = {
  default: DedupStrategyName;
  strategies: { name: DedupStrategyName; description: string }[];
  fields: string[];
  sources: DedupSource[];
};
export type DedupChangeRequest = { source: string; strategy: DedupStrategyName; fields: string[] };
export type DedupPreview = {
  source: string;
  from: { strategy: DedupStrategyName; version: number };
  to: { strategy: DedupStrategyName; version: number; fields: string[] };
  summary: string;
  issues_before: number;
  issues_after: number;
  merge_groups: number;
  issues_merged_away: number;
  issues_split: number;
  new_issues_from_split: number;
  skipped_multi_source: number;
  triage_conflicts: number;
  conflicts: string[];
  examples: {
    kind: "merge" | "split";
    issues: string[];
    issue_count: number;
    titles: string[];
    occurrences: number;
  }[];
  digest: string;
  changes_anything: boolean;
};
export type DedupApplied = { source: string; version: number; effect: Record<string, number>; summary: string };
export type DedupHistoryEntry = {
  source: string;
  version: number;
  strategy: DedupStrategyName;
  fields: string[];
  note: string | null;
  created_by: string | null;
  created_at: string;
  effect: Record<string, number | string>;
};

export type ProjectTest = {
  id: string;
  name: string;
  parser: string | null;
  engagement_id: string;
  engagement_name: string;
  engagement_type: string;
  last_import: { id: string; status: ImportStatus; created_at: string; counts: ImportCounts } | null;
};

export type RevertView = { import_id: string; status: ImportStatus; restored: number; deleted: number; skipped: number };

/** What the API sends back (422) when a file's format could not be identified with confidence. */
export type FormatCandidates = {
  message: string;
  detected: { parser: string; confidence: number }[];
  available: string[];
};
