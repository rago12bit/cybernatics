import type { Finding, FindingsPage, FindingsQuery, ScanView } from "./types";

export const EXPORT_PAGE = 500; // the API's maximum page size

/** Page through every finding matching the filters (bounded), oldest-safe and cancellable. */
export async function collectAll(
  fetchPage: (q: FindingsQuery, limit: number) => Promise<FindingsPage>,
  q: FindingsQuery,
  maxItems = 20_000,
): Promise<Finding[]> {
  const out: Finding[] = [];
  for (let page = 0; out.length < maxItems; page++) {
    const r = await fetchPage({ ...q, page }, EXPORT_PAGE);
    out.push(...r.items);
    if (r.items.length === 0 || out.length >= r.total) break;
  }
  return out.slice(0, maxItems);
}

/** A self-describing JSON export: enough context to interpret the findings without the app. */
export function exportPayload(scan: ScanView, findings: Finding[], q: FindingsQuery) {
  return {
    generated_by: "Bulwark",
    exported_at: new Date().toISOString(),
    scan: {
      id: scan.id,
      source: scan.source_label,
      status: scan.status,
      raw_findings: scan.raw_findings,
      unique_findings: scan.unique_findings,
      dedup_rate: scan.dedup_rate,
      tool_status: Object.fromEntries(Object.entries(scan.tool_status).map(([t, v]) => [t, v.status])),
    },
    filters: { severity: q.severity, category: q.category || null, tool: q.tool || null, path: q.path || null, sort: q.sort },
    count: findings.length,
    findings,
  };
}

export function exportFilename(scan: ScanView): string {
  const slug = scan.source_label.replace(/^https?:\/\//, "").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "scan";
  return `bulwark-${slug}-findings.json`;
}

/** Trigger a browser download of a Blob. The object URL is revoked after the download has started. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
