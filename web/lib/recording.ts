import data from "./juiceshop-demo-data.json";
import type { Finding, ScanView } from "./types";

// The recorded Juice Shop scan (scripts/record-juiceshop.py): one release, scanned as source by the
// default scanners and as a running container by a passive DAST campaign's tools. Every number the
// site shows about it is read from here, never typed into a page.

export type RefusedEgress = { host: string; port: number; protocol: string; attempts: number };
export type Provenance = {
  app: string;
  version: string;
  commit: string;
  image: string;
  recorded_on: string;
  bulwark_version: string;
  made_by: string;
};

export const provenance = data.provenance as Provenance;
export const codeScan = data.scan as unknown as ScanView;
export const codeFindings = data.findings as unknown as Finding[];
export const runtimeScan = data.runtime.scan as unknown as ScanView;
export const runtimeFindings = data.runtime.findings as unknown as Finding[];
export const refusedEgress = data.runtime.refused_egress as RefusedEgress[];

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function severityRows(scan: ScanView): { severity: string; count: number }[] {
  return SEVERITY_ORDER.map((s) => ({ severity: s, count: scan.severity_counts[s] ?? 0 })).filter((r) => r.count > 0);
}

/** Tools that ran, slowest last, with what each reported. Skipped tools are kept with their reason. */
export function toolRows(scan: ScanView): { name: string; status: string; findings: number; seconds: number | null; note: string | null }[] {
  return Object.entries(scan.tool_status)
    .map(([name, t]) => ({
      name,
      status: t.status,
      findings: t.findings ?? 0,
      seconds: t.duration_seconds ?? null,
      note: t.error ?? (t.warnings && t.warnings.length ? t.warnings.join("; ") : null),
    }))
    .sort((a, b) => (a.seconds ?? Infinity) - (b.seconds ?? Infinity));
}

/** Distinct fingerprints: what Issues are matched by. Lower than the scan's own count when a scanner
 * reports one rule more than once in one place (Semgrep on one line, ZAP with different evidence). */
export function fingerprintCount(findings: Finding[]): number {
  return new Set(findings.map((f) => f.fingerprint)).size;
}

export function refusedTotal(): number {
  return refusedEgress.reduce((n, e) => n + e.attempts, 0);
}

/** "sha256:123acb31ed8b…" -- enough to check against `docker image inspect`, short enough to read. */
export function shortDigest(image: string): string {
  const at = image.indexOf("@");
  const digest = at >= 0 ? image.slice(at + 1) : image;
  return digest.length > 19 ? `${digest.slice(0, 19)}…` : digest;
}

/** Per-tool bar width class, in the 5% steps the stylesheet defines (inline styles are blocked by the CSP). */
export function widthClass(n: number, max: number): string {
  if (max <= 0 || n <= 0) return "w-4";
  return `w-${Math.max(4, Math.min(100, Math.round((n / max) * 20) * 5))}`;
}
