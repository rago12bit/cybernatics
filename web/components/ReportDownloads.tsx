"use client";

import { useState } from "react";
import { fetchReport, type ReportFormat } from "@/lib/api";
import { saveBlob } from "@/lib/export";

const FORMATS: { id: ReportFormat; label: string; hint: string }[] = [
  { id: "pdf", label: "PDF", hint: "A report to read or share" },
  { id: "html", label: "HTML", hint: "One self-contained file, no scripts" },
  { id: "sarif", label: "SARIF", hint: "For GitHub Code Scanning and other tools" },
];

/** Whole-scan report downloads (every finding, ranked by risk), unlike the filtered JSON export. */
export function ReportDownloads({ scanId }: { scanId: string }) {
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function download(format: ReportFormat) {
    setBusy(format);
    setError(null);
    try {
      saveBlob(await fetchReport(scanId, format), `bulwark-${scanId.slice(0, 8)}.${format}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Download failed");
    } finally {
      setBusy(null);
    }
  }
  return (
    <div className="downloads" role="group" aria-label="Download full report">
      <span className="label dimmed">Report</span>
      {FORMATS.map((f) => (
        <button key={f.id} type="button" className="btn sm" title={f.hint} disabled={busy !== null} onClick={() => download(f.id)}>
          {busy === f.id ? "Preparing…" : f.label}
        </button>
      ))}
      {error && <span className="error small" role="alert">{error}</span>}
    </div>
  );
}
