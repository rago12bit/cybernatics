import type { FindingsPage, FindingsQuery, ScanSummary, ScanView } from "./types";
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
