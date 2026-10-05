import type { RiskAcceptance, RiskAcceptanceInput, RiskAcceptancePolicy, SlaBand, SlaOverview, ConnectorInput, ConnectorKind, ConnectorView, AnalyzeResult, MappingPreview, MappingSpec, SavedMapping, CvssScore, CweEntry,
  EvidenceFile, ManualFindingInput, ManualFindingView, ManualRecorded, ProjectRoutes, DedupApplied, DedupChangeRequest, DedupHistoryEntry, DedupOverview, DedupPreview,
  ImportCreated, ImportView, ParserInfo, ProjectTest, RevertView,
  AssetSummary, AssetVerification, AttackPath, BulkTriageResult,
  StrideRow, ThreatModel, RetentionSettings, Citation, CopilotConversation, CopilotMessage, CostSummary, DependenciesView, Finding, FindingsPage, FindingsQuery, GenerateHypothesesResult, Guidance, GuidanceApi, Hypothesis, IssueHistoryEvent, ProjectOverview, Remediation, ScanComparison, ScanCost, ScanSummary, ScanView, TriageAssistantView, TriageStatus, VerifiedFixStarted, VerifiedFixView } from "./types";
import { findingsQueryString } from "./format";

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
  sort: "severity" | "path" | "risk";
}

export type OpenSlaState = "on_track" | "due_soon" | "breached";

function issuesQueryString(q: IssuesQuery, limit?: number, offset?: number): string {
  const p = new URLSearchParams();
  q.severity.forEach((s) => p.append("severity", s));
  if (q.category) p.append("category", q.category);
  q.triage.forEach((t) => p.append("triage", t));
  (q.sla ?? []).forEach((s) => p.append("sla", s));
  p.set("sort", q.sort);
  if (limit != null) p.set("limit", String(limit));
  if (offset != null) p.set("offset", String(offset));
  return p.toString();
}

export const listIssues = (assetId: string, q: IssuesQuery, limit = 200, offset = 0) =>
  request<FindingsPage>(`/assets/${encodeURIComponent(assetId)}/issues?${issuesQueryString(q, limit, offset)}`);

export const getSla = (assetId: string) =>
  request<SlaOverview>(`/v2/projects/${encodeURIComponent(assetId)}/sla`);

export const saveSla = (assetId: string, body: { enabled: boolean; bands: Record<string, SlaBand>; note?: string }) =>
  request<SlaOverview>(`/v2/projects/${encodeURIComponent(assetId)}/sla`, {
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
  if (o.engagementType) form.set("engagement_type", o.engagementType);
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
