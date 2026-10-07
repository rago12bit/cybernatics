"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useState } from "react";
import { ApiError, createReport, listReportTemplates, listReports } from "@/lib/api";
import { scheduleWords, type Report, type ReportTemplate } from "@/lib/reports";
import { Button } from "@/design-system/primitives/Button";
import "../dashboard/dashboard.css";
import "./reports.css";

/* Reports (plan §48.3): every report, and a new one from a template. */
export function ReportsScreen() {
  const id = useId();
  const router = useRouter();
  const [reports, setReports] = useState<Report[] | null>(null);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [template, setTemplate] = useState("program-weekly");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    listReports().then(setReports, (e) => setError(e instanceof ApiError ? e.message : "Could not load reports."));
    listReportTemplates().then(setTemplates, () => setTemplates([]));
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await createReport({ template });
      router.push(`/app/reports/${encodeURIComponent(r.id)}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the report.");
      setBusy(false);
    }
  }

  const chosen = templates.find((t) => t.id === template);
  return (
    <div className="dash rep">
      <span className="eyebrow">Reports</span>
      <h1>Reports</h1>
      <p className="dash-muted">Build a report from blocks, generate a signed PDF, share it by a link that expires, or send it on a schedule.</p>
      {error && <p role="alert" className="dash-error">{error}</p>}
      <form className="rep-panel" onSubmit={create} aria-labelledby={`${id}-new`}>
        <h2 id={`${id}-new`}>New report</h2>
        <label htmlFor={`${id}-tpl`} className="dash-label">Start from</label>
        <div className="dash-row">
          <select id={`${id}-tpl`} value={template} onChange={(e) => setTemplate(e.target.value)} aria-describedby={`${id}-desc`}>
            {templates.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <Button type="submit" variant="primary" disabled={busy || !templates.length}>Create</Button>
        </div>
        <p id={`${id}-desc`} className="dash-muted dash-small">{chosen?.description ?? ""}</p>
      </form>
      <section aria-labelledby={`${id}-list`}>
        <h2 id={`${id}-list`}>Your organization&apos;s reports</h2>
        {!reports && !error && <p role="status">Loading…</p>}
        {reports?.length === 0 && <p className="dash-muted">No reports yet.</p>}
        {reports && reports.length > 0 && (
          <table className="dash-table">
            <caption className="sr-only">Reports</caption>
            <thead><tr><th scope="col">Report</th><th scope="col">Covers</th><th scope="col">Schedule</th><th scope="col">Summary</th></tr></thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <th scope="row"><Link href={`/app/reports/${encodeURIComponent(r.id)}`}>{r.name}</Link></th>
                  <td>The last {r.period_days} days</td>
                  <td>{scheduleWords(r.schedule)}</td>
                  <td>{r.summary_needs_review ? <span className="rep-warn">AI draft to review</span> : "Ready"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
