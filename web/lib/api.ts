import type { VexJustification, AsvsBenchmark, ComplianceFramework, EvidencePack, EvidencePreview, ProjectVex, VexDrafted, VexStatement, AdvisoryFeeds, AdvisoryImpact, AdvisoryIssuesCreated, AdvisorySummary, ProjectOwner, CalendarKind, CalendarView, ComponentSearch, LibrarySummary, Inbox, IssueGroupSummary, IssueTicket, NotificationPrefsView, RuleTemplate, TicketConfigInput, TicketConfigView, Watchers, IssueOwner, Rule, RuleDryRun, RuleInput, RuleRun, RulesCatalogue, ChecklistCatalogue, ChecklistItem, ChecklistResult, ChecklistSummary, Engagement, EngagementDetail, EngagementInput, Mention, NoteFile, NotesView, Person, Portfolio, Retest, RetestAction, TagsView, PriorityBand, PriorityContext, PriorityOverview, PriorityPreview, RiskAcceptance, RiskAcceptanceInput, RiskAcceptancePolicy, SlaBand, SlaBasis, SlaOverview, ConnectorInput, ConnectorKind, ConnectorView, AnalyzeResult, MappingPreview, MappingSpec, SavedMapping, CvssScore, CweEntry,
  EvidenceFile, ManualFindingInput, ManualFindingView, ManualRecorded, ProjectRoutes, DedupApplied, DedupChangeRequest, DedupHistoryEntry, DedupOverview, DedupPreview,
  ImportCreated, ImportView, ParserInfo, ProjectTest, RevertView,
  AssetSummary, AssetVerification, AttackPath, BulkTriageResult,
  StrideRow, ThreatModel, RetentionSettings, Citation, CopilotConversation, CopilotMessage, CostSummary, DependenciesView, Finding, FindingsPage, FindingsQuery, GenerateHypothesesResult, Guidance, GuidanceApi, Hypothesis, IssueHistoryEvent, ProjectOverview, Remediation, ScanComparison, ScanCost, ScanSummary, ScanView, TriageAssistantView, TriageStatus, VerifiedFixStarted, VerifiedFixView } from "./types";
import type { AssignedIssue, Dashboard, DashboardList, Me, MetricIssue, MetricResult, MyEngagement, Role, UnitOverview, UnitSummary, Widget } from "./dashboard";
import { findingsQueryString } from "./format";
import type { Block, NewLink, Report as ReportT, ReportLink as ReportLinkT, ReportRun as ReportRunT, ReportTemplate, Schedule } from "./reports";

export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
const TOKEN_KEY = "bulwark.token";

export class ApiError extends Error {
  /** `data` is the structured error body when the API sent one (e.g. the candidate formats when a
   * file's format could not be identified) -- `message` alone would lose it. */
  constructor(public status: number, message: string, public data?: unknown) {
    super(message);
  }
}

const AUTH_EVENT = "bulwark:auth";
const notifyAuth = () => {
  try {
    window.dispatchEvent(new Event(AUTH_EVENT));
  } catch {
    /* no window (SSR) */
  }
};
/** Run `cb` whenever this tab signs in or out, so the header and the app never disagree about it. */
export function onAuthChange(cb: () => void): () => void {
  window.addEventListener(AUTH_EVENT, cb);
  return () => window.removeEventListener(AUTH_EVENT, cb);
}

// sessionStorage: the token lives only for this tab and is never written to disk or a URL.
export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}
export function setToken(t: string): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, t);
  } catch {
    /* storage unavailable: the user will be asked again */
  }
  notifyAuth();
}
export function clearToken(): void {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
  notifyAuth();
}

async function request<T>(path: string, init: RequestInit = {}, token = getToken()): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, `Cannot reach the Bulwark API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    let data: unknown;
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") detail = body.detail;
      else if (body?.detail && typeof body.detail === "object") {
        data = body.detail;
        if (typeof body.detail.message === "string") detail = body.detail.message;
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail, data);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const verifyToken = (token: string) => request<ScanSummary[]>("/scans?limit=1", {}, token);
export const listScans = () => request<ScanSummary[]>("/scans?limit=15");
export const getScan = (id: string) => request<ScanView>(`/scans/${encodeURIComponent(id)}`);
export const getFindings = (id: string, q: FindingsQuery, limit?: number) =>
  request<FindingsPage>(`/scans/${encodeURIComponent(id)}/findings?${findingsQueryString(q, limit)}`);
export const compareScans = (id: string, against: string) =>
  request<ScanComparison>(
    `/scans/${encodeURIComponent(id)}/compare?against=${encodeURIComponent(against)}`,
  );

export function createGitScan(url: string, tools: string[]) {
  return request<{ id: string; status: string }>("/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source: { type: "git", url }, tools }),
  });
}

export function uploadScan(file: File, tools: string[]) {
  const form = new FormData();
  form.set("archive", file);
  form.set("tools", tools.join(","));
  return request<{ id: string; status: string }>("/scans/upload", { method: "POST", body: form });
}

export const wsUrl = (id: string) => `${API_URL.replace(/^http/, "ws")}/scans/${encodeURIComponent(id)}/ws`;

export type ReportFormat = "sarif" | "html" | "pdf";

/** Fetch a full-scan report with the bearer token (a plain link could not send it) as a Blob. */
export async function fetchReport(id: string, format: ReportFormat): Promise<Blob> {
  const token = getToken();
  let res: Response;
  try {
    res = await fetch(`${API_URL}/scans/${encodeURIComponent(id)}/export?format=${format}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch {
    throw new ApiError(0, `Cannot reach the Bulwark API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return res.blob();
}

/** Reference guidance plus any cached AI suggestion. Calls no model, so it is safe to load on open. */
export const getGuidance = (scanId: string, findingId: string) =>
  request<Guidance>(`/scans/${encodeURIComponent(scanId)}/guidance?finding_id=${encodeURIComponent(findingId)}`);

/** Generate an AI suggestion. This sends data to the model provider, so it only ever runs on a click. */
export const requestSuggestion = (scanId: string, findingId: string) =>
  request<Remediation>(`/scans/${encodeURIComponent(scanId)}/suggestion`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId }),
  });

export const liveGuidance: GuidanceApi = { get: getGuidance, request: requestSuggestion };

/** Projects (plan §27): §28.1's overview screen (Week 33) is built entirely from these two calls. */
export const listAssets = () => request<AssetSummary[]>("/assets?limit=50");
export const getAssetOverview = (id: string) =>
  request<ProjectOverview>(`/assets/${encodeURIComponent(id)}/overview`);

/** The Dependencies screen (plan §20.5): the asset's latest SBOM, if any scan opted "syft" in. */
export const getDependencies = (assetId: string) =>
  request<DependenciesView>(`/assets/${encodeURIComponent(assetId)}/dependencies`);

/** The issues table (plan §28.3, Week 34): the asset's currently-open issues, joined with triage
 * state. `triage` omitted is the active queue; pass e.g. ["accepted"] to see triaged-away issues. */
export interface IssuesQuery {
  severity: string[];
  category: string;
  triage: TriageStatus[];
  /** SLA states to filter to (plan §44.1). Optional: views saved before Week 61 have none. */
  sla?: OpenSlaState[];
  /** Priority bands to filter to (plan §44.3). Optional: views saved before Week 63 have none. */
  priority?: PriorityBand[];
  /** Tags, set on the issue, its project or its portfolio (plan §49). */
  tag?: string[];
  sort: "severity" | "path" | "risk";
}

export type OpenSlaState = "on_track" | "due_soon" | "breached";

function issuesQueryString(q: IssuesQuery, limit?: number, offset?: number): string {
  const p = new URLSearchParams();
  q.severity.forEach((s) => p.append("severity", s));
  if (q.category) p.append("category", q.category);
  q.triage.forEach((t) => p.append("triage", t));
  (q.sla ?? []).forEach((s) => p.append("sla", s));
  (q.priority ?? []).forEach((b) => p.append("priority", b));
  (q.tag ?? []).forEach((t) => p.append("tag", t));
  p.set("sort", q.sort);
  if (limit != null) p.set("limit", String(limit));
  if (offset != null) p.set("offset", String(offset));
  return p.toString();
}

export const listIssues = (assetId: string, q: IssuesQuery, limit = 200, offset = 0) =>
  request<FindingsPage>(`/assets/${encodeURIComponent(assetId)}/issues?${issuesQueryString(q, limit, offset)}`);

export const getSla = (assetId: string) =>
  request<SlaOverview>(`/v2/projects/${encodeURIComponent(assetId)}/sla`);

export const saveSla = (assetId: string, body: { enabled: boolean; basis?: SlaBasis; bands: Record<string, SlaBand>; note?: string }) =>
  request<SlaOverview>(`/v2/projects/${encodeURIComponent(assetId)}/sla`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

/** Priority weights (plan §44.3, Week 63). */
export const getPriority = (assetId: string) =>
  request<PriorityOverview>(`/v2/projects/${encodeURIComponent(assetId)}/priority`);

export type PriorityInput = { weights: Record<string, number>; context: PriorityContext; note?: string };

export const previewPriority = (assetId: string, body: PriorityInput) =>
  request<PriorityPreview>(`/v2/projects/${encodeURIComponent(assetId)}/priority/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

/** Accepted, not finished: the API re-ranks every issue in the background (poll getPriority). */
export const savePriority = (assetId: string, body: PriorityInput) =>
  request<PriorityOverview>(`/v2/projects/${encodeURIComponent(assetId)}/priority`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

const jsonPost = (body: unknown) => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const getRiskAcceptancePolicy = () => request<RiskAcceptancePolicy>("/v2/risk-acceptance-policy");

export const requestRiskAcceptance = (assetId: string, body: RiskAcceptanceInput) =>
  request<RiskAcceptance>(`/v2/projects/${encodeURIComponent(assetId)}/risk-acceptances`, jsonPost(body));

export const listRiskAcceptances = (states?: string[]) => {
  const p = new URLSearchParams();
  (states ?? []).forEach((s) => p.append("state", s));
  const q = p.toString();
  return request<RiskAcceptance[]>(`/v2/risk-acceptances${q ? `?${q}` : ""}`);
};

export const listIssueRiskAcceptances = (assetId: string, issueId: string) =>
  request<RiskAcceptance[]>(`/v2/projects/${encodeURIComponent(assetId)}/risk-acceptances?issue_id=${encodeURIComponent(issueId)}`);

export const getRiskAcceptance = (id: string) => request<RiskAcceptance>(`/v2/risk-acceptances/${encodeURIComponent(id)}`);

export type RiskAcceptanceAction = "approve" | "reject" | "withdraw" | "expire" | "reinstate";

export const actOnRiskAcceptance = (id: string, action: RiskAcceptanceAction, note?: string) =>
  request<RiskAcceptance>(`/v2/risk-acceptances/${encodeURIComponent(id)}/${action}`, jsonPost(note ? { note } : {}));

export const extendRiskAcceptance = (id: string, expires_at: string, justification?: string) =>
  request<RiskAcceptance>(`/v2/risk-acceptances/${encodeURIComponent(id)}/extend`, jsonPost({ expires_at, justification }));

export const addRiskAcceptanceProof = (id: string, file: File) => {
  const form = new FormData();
  form.append("file", file);
  return request<{ id: string; file_name: string }>(`/v2/risk-acceptances/${encodeURIComponent(id)}/attachments`, { method: "POST", body: form });
};

export const getIssue = (assetId: string, issueId: string) =>
  request<Finding>(`/assets/${encodeURIComponent(assetId)}/issues/${encodeURIComponent(issueId)}`);

export const getIssueHistory = (assetId: string, issueId: string) =>
  request<IssueHistoryEvent[]>(`/assets/${encodeURIComponent(assetId)}/issues/${encodeURIComponent(issueId)}/history`);

export interface TriageAction {
  action: "not_a_risk" | "accepted" | "reopen";
  reason?: string;
  expires_at?: string;
  /** For a dependency Issue marked not a risk: why, in OpenVEX's vocabulary (plan §46.3). */
  justification?: VexJustification;
}

export const triageIssue = (assetId: string, issueId: string, body: TriageAction) =>
  request<{ triage_status: TriageStatus }>(`/assets/${encodeURIComponent(assetId)}/issues/${encodeURIComponent(issueId)}/triage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

// The verified-fix agent (plan §21.2/§28.4): propose, verify, and -- only once a human approves --
// open a pull request. Never auto-merged.
const fixPath = (assetId: string, issueId: string, suffix = "") =>
  `/assets/${encodeURIComponent(assetId)}/issues/${encodeURIComponent(issueId)}/verified-fix${suffix}`;

export interface StartVerifiedFixOptions {
  run_tests?: boolean;
  test_image?: string;
  test_command?: string;
}

export const startVerifiedFix = (assetId: string, issueId: string, opts: StartVerifiedFixOptions = {}) =>
  request<VerifiedFixStarted>(fixPath(assetId, issueId), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opts),
  });

/** `null` (not thrown) when no verified-fix run exists yet for this issue -- a normal state, the
 * same "empty, not an error" shape `getDependencies` already uses. */
export async function getVerifiedFix(assetId: string, issueId: string): Promise<VerifiedFixView | null> {
  try {
    return await request<VerifiedFixView>(fixPath(assetId, issueId));
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

export const approveVerifiedFix = (assetId: string, issueId: string) =>
  request<{ status: string }>(fixPath(assetId, issueId, "/approve"), { method: "POST" });

export const rejectVerifiedFix = (assetId: string, issueId: string) =>
  request<{ status: string }>(fixPath(assetId, issueId, "/reject"), { method: "POST" });

export const bulkTriageIssues = (assetId: string, issueIds: string[], body: TriageAction) =>
  request<BulkTriageResult>(`/assets/${encodeURIComponent(assetId)}/issues/bulk-triage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ issue_ids: issueIds, ...body }),
  });

// The triage assistant (plan §21.3): an advisory model verdict, never a human triage decision.
const triageAssistantPath = (assetId: string, issueId: string) =>
  `/assets/${encodeURIComponent(assetId)}/issues/${encodeURIComponent(issueId)}/triage-assistant`;

/** `null` (not thrown) when no verdict has been generated yet -- the normal starting state. */
export async function getTriageAssessment(assetId: string, issueId: string): Promise<TriageAssistantView | null> {
  try {
    return await request<TriageAssistantView>(triageAssistantPath(assetId, issueId));
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

/** Generates a fresh verdict. This sends the finding's code to the model provider. */
export const requestTriageAssessment = (assetId: string, issueId: string) =>
  request<TriageAssistantView>(triageAssistantPath(assetId, issueId), { method: "POST" });

// The Hypotheses lane (plan §21.4): off by default, a separate tab, never in the main issue list
// until a person promotes one.
export const listHypotheses = (assetId: string, status?: Hypothesis["status"]) =>
  request<Hypothesis[]>(
    `/assets/${encodeURIComponent(assetId)}/hypotheses${status ? `?status=${status}` : ""}`,
  );

/** Re-checks out the asset's latest scan and asks the model about every candidate it finds. */
export const generateHypotheses = (assetId: string) =>
  request<GenerateHypothesesResult>(`/assets/${encodeURIComponent(assetId)}/hypotheses/generate`, {
    method: "POST",
  });

export const promoteHypothesis = (assetId: string, hypothesisId: string) =>
  request<{ issue_id: string }>(
    `/assets/${encodeURIComponent(assetId)}/hypotheses/${encodeURIComponent(hypothesisId)}/promote`,
    { method: "POST" },
  );

export const dismissHypothesis = (assetId: string, hypothesisId: string) =>
  request<{ status: string }>(
    `/assets/${encodeURIComponent(assetId)}/hypotheses/${encodeURIComponent(hypothesisId)}/dismiss`,
    { method: "POST" },
  );

// Attack paths (plan §21.6): always computable from the project's own open issues, with a
// best-effort narrative on top when a model is configured server-side (never a hard requirement).
export const listAttackPaths = (assetId: string) =>
  request<AttackPath[]>(`/assets/${encodeURIComponent(assetId)}/attack-paths`);

// Threat model draft (plan §21.7): deterministic, no model call, auto-generated on first access.
export const getThreatModel = (assetId: string) =>
  request<ThreatModel>(`/assets/${encodeURIComponent(assetId)}/threat-model`);

export const regenerateThreatModel = (assetId: string) =>
  request<ThreatModel>(`/assets/${encodeURIComponent(assetId)}/threat-model/regenerate`, {
    method: "POST",
  });

export const saveThreatModel = (assetId: string, mermaid: string, stride: StrideRow[]) =>
  request<ThreatModel>(`/assets/${encodeURIComponent(assetId)}/threat-model`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mermaid, stride }),
  });

// Data retention (plan §22.2): how long this organization keeps a scan's encrypted artifacts
// before crypto-shredding them. Always has a value -- the plan's own default when never set.
export const getRetentionSettings = () => request<RetentionSettings>("/settings/retention");

export const saveRetentionSettings = (retentionDays: number) =>
  request<RetentionSettings>("/settings/retention", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ retention_days: retentionDays }),
  });

// Web/DAST target ownership verification (plan §22.4): registering a target returns the proof-of-
// control instructions; nothing can scan it until POST .../verify passes a live check.
export const registerWebAsset = (domain: string, method: "dns_txt" | "well_known") =>
  request<AssetVerification>("/assets/web", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, method }),
  });

export const getAssetVerification = (assetId: string) =>
  request<AssetVerification>(`/assets/${encodeURIComponent(assetId)}/verification`);

export const verifyAsset = (assetId: string) =>
  request<AssetVerification>(`/assets/${encodeURIComponent(assetId)}/verify`, { method: "POST" });

// DAST campaigns (plan §22.4, Week 49 task 3): "passive" (ZAP baseline) runs once ownership
// verification passes; "active" (adds curated Nuclei) is additionally rate-limited server-side.
// Cost-per-scan dashboard (plan §23, Week 50): an estimate, computed fresh on every call -- see
// ScanCost/CostSummary's own doc comments in ./types.
export const getScanCost = (scanId: string) =>
  request<ScanCost>(`/scans/${encodeURIComponent(scanId)}/cost`);

export const getCostSummary = (days: number = 30) =>
  request<CostSummary>(`/costs/summary?days=${encodeURIComponent(days)}`);

export const listDastCampaigns = (assetId: string) =>
  request<ScanSummary[]>(`/assets/${encodeURIComponent(assetId)}/campaigns`);

export const startDastCampaign = (assetId: string, mode: "passive" | "active") =>
  request<{ id: string; status: string }>(`/assets/${encodeURIComponent(assetId)}/campaigns`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode }),
  });

// The security copilot (plan §21.5): tool-grounded, cited chat about one project.
export const startCopilotConversation = (
  assetId: string,
  context?: { context_kind: "issue" | "scan"; context_id: string },
) =>
  request<CopilotConversation>(`/assets/${encodeURIComponent(assetId)}/copilot/conversations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(context ?? {}),
  });

export const postCopilotMessage = (assetId: string, conversationId: string, question: string) =>
  request<CopilotMessage>(
    `/assets/${encodeURIComponent(assetId)}/copilot/conversations/${encodeURIComponent(conversationId)}/messages`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question }) },
  );

export const listCopilotMessages = (assetId: string, conversationId: string) =>
  request<CopilotMessage[]>(
    `/assets/${encodeURIComponent(assetId)}/copilot/conversations/${encodeURIComponent(conversationId)}/messages`,
  );

// --- Importing reports (Week 54, plan §42.1, ADR-0040) ---------------------------------------------

export type ImportOptions = {
  /** Skip format detection: the format the person picked. */
  parser?: string;
  /** Test name; the server names it after the format when absent. */
  test?: string;
  engagementType?: "import" | "assessment";
  engagementName?: string;
  /** An existing engagement to import into (Week 64): overrides `engagementType`. */
  engagement?: string;
  closeMissing: boolean;
  scope: "test" | "engagement";
  /** Count what would change and save nothing; the file is kept until confirmed or cancelled. */
  preview: boolean;
};

export function startImport(assetId: string, file: File, o: ImportOptions) {
  const form = new FormData();
  form.set("project", assetId);
  form.set("preview", String(o.preview));
  form.set("close_missing", String(o.closeMissing));
  form.set("scope", o.scope);
  if (o.parser) form.set("parser", o.parser);
  if (o.test) form.set("test", o.test);
  if (o.engagement) form.set("engagement", o.engagement);
  else if (o.engagementType) form.set("engagement_type", o.engagementType);
  if (o.engagementName) form.set("engagement_name", o.engagementName);
  form.set("file", file); // last, so the server sees the options before the (large) body
  return request<ImportCreated>("/v2/ingest", { method: "POST", body: form });
}
export const getImport = (id: string) => request<ImportView>(`/v2/imports/${encodeURIComponent(id)}`);
export const confirmImport = (id: string) =>
  request<ImportView>(`/v2/imports/${encodeURIComponent(id)}/confirm`, { method: "POST" });
export const cancelImport = (id: string) =>
  request<ImportView>(`/v2/imports/${encodeURIComponent(id)}/cancel`, { method: "POST" });
export const revertImport = (id: string) =>
  request<RevertView>(`/v2/imports/${encodeURIComponent(id)}/revert`, { method: "POST" });
export const listParsers = () => request<ParserInfo[]>("/v2/parsers");

// --- The universal mapper (Week 59, plan §42.4, ADR-0043) -----------------------------------------
export function analyzeSample(file: File, o: { useModel: boolean; source?: string }) {
  const form = new FormData();
  form.set("use_model", String(o.useModel));
  if (o.source) form.set("source", o.source);
  form.set("file", file);
  return request<AnalyzeResult>("/v2/mappings/analyze", { method: "POST", body: form });
}
export function previewMapping(file: File, spec: MappingSpec, signal?: AbortSignal) {
  const form = new FormData();
  form.set("spec", JSON.stringify(spec));
  form.set("file", file);
  return request<MappingPreview>("/v2/mappings/preview", { method: "POST", body: form, signal });
}
export const saveMapping = (body: { name: string; spec: MappingSpec; proposed_by?: string | null; sample_digest?: string }) =>
  request<SavedMapping>("/v2/mappings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
// --- Manual findings (Week 59, plan §43.2, ADR-0044) ----------------------------------------------
export const scoreCvss4 = (vector: string, signal?: AbortSignal) =>
  request<CvssScore>("/v2/cvss/v4", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ vector }),
    signal,
  });
export const searchCwe = (q: string) => request<CweEntry[]>(`/v2/cwe?q=${encodeURIComponent(q)}&limit=15`);
export const listRoutes = (assetId: string) =>
  request<ProjectRoutes>(`/v2/projects/${encodeURIComponent(assetId)}/routes`);
export const recordManualFinding = (assetId: string, body: ManualFindingInput) =>
  request<ManualRecorded>(`/v2/projects/${encodeURIComponent(assetId)}/manual-findings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const listManualFindings = (assetId: string, issueId?: string) =>
  request<ManualFindingView[]>(
    `/v2/projects/${encodeURIComponent(assetId)}/manual-findings${issueId ? `?issue_id=${encodeURIComponent(issueId)}` : ""}`,
  );
export function uploadEvidence(manualId: string, file: File) {
  const form = new FormData();
  form.set("file", file);
  return request<EvidenceFile>(`/v2/manual-findings/${encodeURIComponent(manualId)}/attachments`, {
    method: "POST",
    body: form,
  });
}
/** A short-lived link; following it downloads the file (it is never shown in the page). */
export async function evidenceDownloadUrl(attachmentId: string): Promise<string> {
  const { url } = await request<{ url: string; expires_at: string }>(
    `/v2/attachments/${encodeURIComponent(attachmentId)}/link`,
    { method: "POST" },
  );
  return url.startsWith("http") ? url : `${API_URL}${url}`;
}

// --- Connectors (Week 60, plan §42.5, §55.7, ADR-0045) ---------------------------------------------
export const listConnectorKinds = () => request<ConnectorKind[]>("/v2/connector-kinds");
export const listConnectors = () => request<ConnectorView[]>("/v2/connectors");
export const getConnector = (id: string) => request<ConnectorView>(`/v2/connectors/${encodeURIComponent(id)}`);
export const createConnector = (body: ConnectorInput) =>
  request<ConnectorView>("/v2/connectors", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const updateConnector = (id: string, body: Partial<{ enabled: boolean; interval_minutes: number; close_on_empty: boolean; credential: string; name: string }>) =>
  request<ConnectorView>(`/v2/connectors/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const runConnector = (id: string) =>
  request<ConnectorView>(`/v2/connectors/${encodeURIComponent(id)}/run`, { method: "POST" });

export const listMappings = () => request<SavedMapping[]>("/v2/mappings");
export const getMapping = (id: string) => request<SavedMapping>(`/v2/mappings/${encodeURIComponent(id)}`);

// --- Matching: deduplication per source (Week 58, plan §42.3, ADR-0042) ---------------------------
const dedupBase = (assetId: string) => `/v2/projects/${encodeURIComponent(assetId)}/dedup`;
export const getDedup = (assetId: string) => request<DedupOverview>(dedupBase(assetId));
export const getDedupHistory = (assetId: string, source?: string) =>
  request<DedupHistoryEntry[]>(
    `${dedupBase(assetId)}/history${source ? `?source=${encodeURIComponent(source)}` : ""}`,
  );
export const previewDedup = (assetId: string, body: DedupChangeRequest) =>
  request<DedupPreview>(`${dedupBase(assetId)}/preview`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const applyDedup = (assetId: string, body: DedupChangeRequest & { digest: string; note?: string }) =>
  request<DedupApplied>(`${dedupBase(assetId)}/apply`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
export const listProjectTests = (assetId: string) =>
  request<ProjectTest[]>(`/v2/projects/${encodeURIComponent(assetId)}/tests`);

// --- Engagements, retests, notes and tags (Week 64, plan §43.1, §43.3, §49) -----------------------

const json = (method: string, body: unknown) => ({
  method,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});
const enc = encodeURIComponent;

export const listChecklists = () => request<ChecklistCatalogue[]>("/v2/checklists");
export const listEngagements = (assetId: string) =>
  request<Engagement[]>(`/v2/projects/${enc(assetId)}/engagements`);
export const createEngagement = (assetId: string, body: EngagementInput) =>
  request<Engagement>(`/v2/projects/${enc(assetId)}/engagements`, json("POST", body));
export const getEngagement = (id: string) => request<EngagementDetail>(`/v2/engagements/${enc(id)}`);
export const updateEngagement = (id: string, body: EngagementInput) =>
  request<Engagement>(`/v2/engagements/${enc(id)}`, json("PATCH", body));
export const getChecklist = (id: string) =>
  request<{ summary: ChecklistSummary; items: ChecklistItem[] }>(`/v2/engagements/${enc(id)}/checklist`);
export const setChecklistItem = (id: string, item: string, status: ChecklistResult | null, note?: string) =>
  request<ChecklistSummary>(`/v2/engagements/${enc(id)}/checklist/${enc(item)}`, json("PUT", { status, note: note || null }));
export const closeEngagement = (id: string, summary?: string) =>
  request<Engagement>(`/v2/engagements/${enc(id)}/close`, json("POST", { summary: summary || null }));

/** The report is a download that needs the token, so it is fetched and handed to the browser as a
 * file -- never rendered in the app. */
export async function downloadReport(id: string, format: "md" | "html"): Promise<void> {
  const token = getToken();
  const res = await fetch(`${API_URL}/v2/engagements/${enc(id)}/report?format=${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new ApiError(res.status, res.status === 404 ? "No report yet." : "Could not download the report.");
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? `report.${format}`;
  const url = URL.createObjectURL(new Blob([await res.blob()], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const getRetest = (issueId: string) => request<Retest>(`/v2/issues/${enc(issueId)}/retest`);
export const retestStep = (issueId: string, action: RetestAction, note?: string) =>
  request<Retest>(`/v2/issues/${enc(issueId)}/retest`, json("POST", { action, note: note || null }));
export const runTargetedRetest = (issueId: string) =>
  request<Retest>(`/v2/issues/${enc(issueId)}/retest/run`, { method: "POST" });

export const listPeople = () => request<Person[]>("/v2/people");
export const listNotes = (issueId: string) => request<NotesView>(`/v2/issues/${enc(issueId)}/notes`);
export const addNote = (issueId: string, body: string, parentId?: string) =>
  request<NotesView>(`/v2/issues/${enc(issueId)}/notes`, json("POST", { body, parent_id: parentId ?? null }));
export const editNote = (noteId: string, body: string) =>
  request<NotesView>(`/v2/notes/${enc(noteId)}`, json("PATCH", { body }));
export const deleteNote = (noteId: string) => request<NotesView>(`/v2/notes/${enc(noteId)}`, { method: "DELETE" });
export function attachToNote(noteId: string, file: File) {
  const form = new FormData();
  form.set("file", file);
  return request<NoteFile>(`/v2/notes/${enc(noteId)}/attachments`, { method: "POST", body: form });
}
export const noteFileLink = (attachmentId: string) =>
  request<{ url: string; expires_at: string }>(`/v2/note-attachments/${enc(attachmentId)}/link`, { method: "POST" });
export const listMentions = () =>
  request<{ mentions: Mention[]; names: Record<string, string> }>("/v2/mentions");

export const getIssueTags = (issueId: string) => request<TagsView>(`/v2/issues/${enc(issueId)}/tags`);
export const setIssueTags = (issueId: string, tags: string[]) =>
  request<TagsView>(`/v2/issues/${enc(issueId)}/tags`, json("PUT", { tags }));
export const getProjectTags = (assetId: string) => request<TagsView>(`/v2/projects/${enc(assetId)}/tags`);
export const setProjectTags = (assetId: string, tags: string[]) =>
  request<TagsView>(`/v2/projects/${enc(assetId)}/tags`, json("PUT", { tags }));
export const setProjectPortfolio = (assetId: string, portfolioId: string | null) =>
  request<TagsView>(`/v2/projects/${enc(assetId)}/portfolio`, json("PUT", { portfolio_id: portfolioId }));
export const listPortfolios = () => request<Portfolio[]>("/v2/portfolios");
export const createPortfolio = (name: string) => request<Portfolio>("/v2/portfolios", json("POST", { name }));
export const setPortfolioTags = (id: string, tags: string[]) =>
  request<Portfolio>(`/v2/portfolios/${enc(id)}/tags`, json("PUT", { tags }));

export const getRulesCatalogue = () => request<RulesCatalogue>("/v2/rules/catalogue");
export const listRules = (projectId?: string) =>
  request<Rule[]>(`/v2/rules${projectId ? `?project_id=${enc(projectId)}` : ""}`);
export const getRule = (id: string) => request<Rule>(`/v2/rules/${enc(id)}`);
export const createRule = (body: RuleInput) => request<Rule>("/v2/rules", json("POST", body));
export const updateRule = (id: string, body: RuleInput) => request<Rule>(`/v2/rules/${enc(id)}`, json("PUT", body));
export const setRuleEnabled = (id: string, enabled: boolean) =>
  request<Rule>(`/v2/rules/${enc(id)}/enabled`, json("PUT", { enabled }));
export const deleteRule = (id: string) => request<void>(`/v2/rules/${enc(id)}`, { method: "DELETE" });
export const testRuleDraft = (body: RuleInput) => request<RuleDryRun>("/v2/rules/test", json("POST", body));
export const testRule = (id: string) => request<RuleDryRun>(`/v2/rules/${enc(id)}/test`, { method: "POST" });
export const listRuleRuns = (q: { rule_id?: string; status?: string; limit?: number } = {}) => {
  const p = new URLSearchParams();
  if (q.rule_id) p.set("rule_id", q.rule_id);
  if (q.status) p.set("status", q.status);
  if (q.limit) p.set("limit", String(q.limit));
  const s = p.toString();
  return request<RuleRun[]>(`/v2/rule-runs${s ? `?${s}` : ""}`);
};
export const confirmRuleRun = (id: string) => request<RuleRun>(`/v2/rule-runs/${enc(id)}/confirm`, { method: "POST" });
export const dismissRuleRun = (id: string) => request<RuleRun>(`/v2/rule-runs/${enc(id)}/dismiss`, { method: "POST" });
export const getIssueOwner = (issueId: string) => request<IssueOwner>(`/v2/issues/${enc(issueId)}/assignee`);
export const setIssueAssignee = (issueId: string, to: string | null) =>
  request<IssueOwner>(`/v2/issues/${enc(issueId)}/assignee`, json("PUT", { to }));
export const setIssuePriority = (issueId: string, band: string | null) =>
  request<IssueOwner>(`/v2/issues/${enc(issueId)}/priority`, json("PUT", { band }));

export const listRuleTemplates = () => request<RuleTemplate[]>("/v2/rules/templates");

export const getInbox = (unread = false) => request<Inbox>(`/v2/notifications${unread ? "?unread=true" : ""}`);
export const markNotificationsRead = (ids?: string[]) =>
  request<{ marked: number; unread: number }>("/v2/notifications/read", json("POST", ids ? { ids } : {}));
export const getMyNotificationPrefs = () => request<NotificationPrefsView>("/v2/notification-prefs");
export const saveMyNotificationPrefs = (body: { modes: Record<string, Record<string, string>>; digest_hour: number; email: string | null }) =>
  request<NotificationPrefsView>("/v2/notification-prefs", json("PUT", body));
export const getTeamNotificationPrefs = () => request<NotificationPrefsView>("/v2/notification-prefs/team");
export const saveTeamNotificationPrefs = (body: { modes: Record<string, Record<string, string>>; digest_hour: number }) =>
  request<NotificationPrefsView>("/v2/notification-prefs/team", json("PUT", body));
export const getWatchers = (issueId: string) => request<Watchers>(`/v2/issues/${enc(issueId)}/watchers`);
export const watchIssue = (issueId: string) => request<Watchers>(`/v2/issues/${enc(issueId)}/watch`, { method: "PUT" });
export const unwatchIssue = (issueId: string) => request<Watchers>(`/v2/issues/${enc(issueId)}/watch`, { method: "DELETE" });

export const getTicketConfig = (assetId: string) => request<TicketConfigView>(`/v2/projects/${enc(assetId)}/tickets`);
export const saveTicketConfig = (assetId: string, body: TicketConfigInput) =>
  request<TicketConfigView>(`/v2/projects/${enc(assetId)}/tickets`, json("PUT", body));
export const listIssueGroups = (assetId: string) => request<IssueGroupSummary[]>(`/v2/projects/${enc(assetId)}/groups`);
export const getIssueTicket = (issueId: string) => request<IssueTicket>(`/v2/issues/${enc(issueId)}/ticket`);
export const fileIssueTicket = (issueId: string) => request<IssueTicket>(`/v2/issues/${enc(issueId)}/ticket`, { method: "POST" });
export const syncIssueTicket = (issueId: string) => request<IssueTicket>(`/v2/issues/${enc(issueId)}/ticket/sync`, { method: "POST" });
export const setIssueGroup = (issueId: string, body: { group_id?: string | null; name?: string | null }) =>
  request<IssueTicket>(`/v2/issues/${enc(issueId)}/group`, json("PUT", body));

/** The advisory engine (plan §46.2, §55.5). */
export const listAdvisories = (q: { state?: string; q?: string; kev?: boolean } = {}) => {
  const p = new URLSearchParams();
  if (q.state) p.set("state", q.state);
  if (q.q) p.set("q", q.q);
  if (q.kev) p.set("kev", "true");
  const s = p.toString();
  return request<AdvisorySummary[]>(`/v2/advisories${s ? `?${s}` : ""}`);
};
export const getAdvisory = (key: string) => request<AdvisoryImpact>(`/v2/advisories/${encodeURIComponent(key)}`);
export const createAdvisoryIssues = (key: string, projectIds?: string[]) =>
  request<AdvisoryIssuesCreated>(`/v2/advisories/${encodeURIComponent(key)}/issues`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(projectIds ? { project_ids: projectIds } : {}),
  });
export const getAdvisoryFeeds = () => request<AdvisoryFeeds>("/v2/advisory-feeds");
export const getProjectOwner = (id: string) => request<ProjectOwner>(`/v2/projects/${encodeURIComponent(id)}/owner`);
export const setProjectOwner = (id: string, owner: string | null) =>
  request<ProjectOwner>(`/v2/projects/${encodeURIComponent(id)}/owner`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ owner }),
  });

/** The component inventory (plan §46.1): "where do we use this?" */
export const searchComponents = (purl: string, q: { version?: string; projectId?: string } = {}) => {
  const p = new URLSearchParams({ purl });
  if (q.version) p.set("version", q.version);
  if (q.projectId) p.set("project_id", q.projectId);
  return request<ComponentSearch>(`/v2/components?${p.toString()}`);
};
export const listLibraries = (q = "", limit = 20) =>
  request<LibrarySummary[]>(`/v2/libraries?${new URLSearchParams({ q, limit: String(limit) }).toString()}`);

export const getCalendar = (from: string, to: string, q: { projectId?: string; kinds?: CalendarKind[] } = {}) => {
  const p = new URLSearchParams({ from, to });
  if (q.projectId) p.set("project_id", q.projectId);
  if (q.kinds) p.set("kinds", q.kinds.join(","));
  return request<CalendarView>(`/v2/calendar?${p.toString()}`);
};

/** VEX (plan §46.3): drafts with evidence, a person's decision, the exports. */
export const draftVex = (key: string) =>
  request<VexDrafted>(`/v2/advisories/${encodeURIComponent(key)}/vex-drafts`, { method: "POST" });
export const decideVex = (id: string, decision: "confirm" | "reject" | "withdraw", note?: string) =>
  request<VexStatement>(`/v2/vex/${enc(id)}/${decision}`, json("POST", { note: note || null }));
export const getProjectVex = (id: string) => request<ProjectVex>(`/v2/projects/${enc(id)}/vex`);

/** A download that needs the token: fetched, then handed to the browser as a file. */
async function download(path: string, fallbackName: string, failure: string): Promise<void> {
  const token = getToken();
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  } catch {
    throw new ApiError(0, `Cannot reach the Bulwark API at ${API_URL}. Is it running?`);
  }
  if (!res.ok) throw new ApiError(res.status, failure);
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(new Blob([await res.blob()], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const downloadVex = (id: string, format: "openvex" | "cyclonedx") =>
  download(`/v2/projects/${enc(id)}/vex/${format}`, `vex.${format}.json`, "Could not download the VEX document.");

/** Compliance (plan §47). */
export const listFrameworks = () => request<ComplianceFramework[]>("/v2/compliance/frameworks");
export const getAsvs = (id: string, level: number) => request<AsvsBenchmark>(`/v2/projects/${enc(id)}/asvs?level=${level}`);
export const setAsvsStatus = (id: string, req: string, body: { status: "met" | "not_met" | "not_applicable" | null; note: string; links: string[] }) =>
  request<{ requirement: string; status: string | null }>(`/v2/projects/${enc(id)}/asvs/${enc(req)}`, json("PUT", body));
export const previewEvidencePack = (body: { start: string; end: string; frameworks: string[] }) =>
  request<EvidencePreview>("/v2/evidence-packs/preview", json("POST", body));
export const createEvidencePack = (body: { start: string; end: string; frameworks: string[] }) =>
  request<EvidencePack>("/v2/evidence-packs", json("POST", body));
export const listEvidencePacks = () => request<EvidencePack[]>("/v2/evidence-packs");
export const downloadEvidencePack = (id: string) =>
  download(`/v2/evidence-packs/${enc(id)}/bundle`, "evidence-pack.zip", "Could not download the evidence pack.");

/** Metrics and dashboards (plan §48.1, §48.2, §55.4). */
export const getMetric = (metric: string, params: URLSearchParams, signal?: AbortSignal) =>
  request<MetricResult>(`/v2/metrics/${enc(metric)}?${params.toString()}`, { signal });
export const getMetricIssues = (params: URLSearchParams) =>
  request<{ rows: MetricIssue[]; next: string | null }>(`/v2/metrics/issues?${params.toString()}`);
export const getMe = () => request<Me>("/v2/me");
export const setMyRole = (role: Role) => request<Me>("/v2/me/role", json("PUT", { role }));
export const listDashboards = () => request<DashboardList>("/v2/dashboards");
export const getDashboard = (id: string) => request<Dashboard>(`/v2/dashboards/${enc(id)}`);
export const createDashboard = (body: { name: string; shared_with?: Role[]; widgets: Widget[] }) =>
  request<Dashboard>("/v2/dashboards", json("POST", body));
export const saveDashboard = (id: string, body: { version: number; name?: string; shared_with?: Role[]; widgets?: Widget[] }) =>
  request<Dashboard>(`/v2/dashboards/${enc(id)}`, json("PUT", body));
export const deleteDashboard = (id: string) => request<void>(`/v2/dashboards/${enc(id)}`, { method: "DELETE" });
export const copyDashboard = (id: string) => request<Dashboard>(`/v2/dashboards/${enc(id)}/copy`, { method: "POST" });
export const listMetrics = () =>
  request<{ id: string; name: string; definition: string; unit: string; period: boolean }[]>("/v2/metrics");
export const getMyAssigned = () => request<{ total: number; rows: AssignedIssue[] }>("/v2/me/assigned");
export const getMyEngagements = () => request<MyEngagement[]>("/v2/me/engagements");
export const listUnitOverviews = () => request<UnitSummary[]>("/v2/portfolio-overviews");
export const getUnitOverview = (id: string) => request<UnitOverview>(`/v2/portfolio-overviews/${enc(id)}`);

/** Reports (plan §48.3). */
export const listReportTemplates = () => request<ReportTemplate[]>("/v2/report-templates");
export const listReports = () => request<ReportT[]>("/v2/reports");
export const getReport = (id: string) => request<ReportT>(`/v2/reports/${enc(id)}`);
export const createReport = (body: { name?: string; template?: string; blocks?: Block[]; period_days?: number }) =>
  request<ReportT>("/v2/reports", json("POST", body));
export const saveReport = (id: string, body: { version: number; name?: string; period_days?: number; blocks?: Block[]; schedule?: Schedule | null }) =>
  request<ReportT>(`/v2/reports/${enc(id)}`, json("PUT", body));
export const deleteReport = (id: string) => request<void>(`/v2/reports/${enc(id)}`, { method: "DELETE" });
export const draftReportSummary = (id: string) => request<ReportT>(`/v2/reports/${enc(id)}/summary/draft`, { method: "POST" });
export const reviewReportSummary = (id: string, version: number, text: string) =>
  request<ReportT>(`/v2/reports/${enc(id)}/summary/review`, json("POST", { version, text }));
export const generateReport = (id: string) => request<ReportRunT>(`/v2/reports/${enc(id)}/runs`, { method: "POST" });
export const listReportRuns = (id: string) => request<ReportRunT[]>(`/v2/reports/${enc(id)}/runs`);
export const downloadReportPdf = (runId: string) =>
  download(`/v2/report-runs/${enc(runId)}/pdf`, "report.pdf", "Could not download the report.");
export const downloadReportSignature = (runId: string) =>
  download(`/v2/report-runs/${enc(runId)}/signature`, "report.pdf.sig", "Could not download the signature.");
export const createReportLink = (runId: string, days: number) =>
  request<NewLink>(`/v2/report-runs/${enc(runId)}/links`, json("POST", { days }));
export const listReportLinks = (runId: string) => request<ReportLinkT[]>(`/v2/report-runs/${enc(runId)}/links`);
export const revokeReportLink = (id: string) => request<ReportLinkT>(`/v2/report-links/${enc(id)}`, { method: "DELETE" });
