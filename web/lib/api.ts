import type { AssetSummary, AssetVerification, AttackPath, BulkTriageResult,
  StrideRow, ThreatModel, RetentionSettings, Citation, CopilotConversation, CopilotMessage, DependenciesView, Finding, FindingsPage, FindingsQuery, GenerateHypothesesResult, Guidance, GuidanceApi, Hypothesis, IssueHistoryEvent, ProjectOverview, Remediation, ScanComparison, ScanSummary, ScanView, TriageAssistantView, TriageStatus, VerifiedFixStarted, VerifiedFixView } from "./types";
import { findingsQueryString } from "./format";

export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
const TOKEN_KEY = "bulwark.token";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
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
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
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
  sort: "severity" | "path" | "risk";
}

function issuesQueryString(q: IssuesQuery, limit?: number, offset?: number): string {
  const p = new URLSearchParams();
  q.severity.forEach((s) => p.append("severity", s));
  if (q.category) p.append("category", q.category);
  q.triage.forEach((t) => p.append("triage", t));
  p.set("sort", q.sort);
  if (limit != null) p.set("limit", String(limit));
  if (offset != null) p.set("offset", String(offset));
  return p.toString();
}

export const listIssues = (assetId: string, q: IssuesQuery, limit = 200, offset = 0) =>
  request<FindingsPage>(`/assets/${encodeURIComponent(assetId)}/issues?${issuesQueryString(q, limit, offset)}`);

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
