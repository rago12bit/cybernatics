"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ApiError, getMetricIssues } from "@/lib/api";
import type { MetricIssue } from "@/lib/dashboard";
import "./dashboard.css";

/* The Issues behind a number on a dashboard (plan §55.4, principle 11): the same filters the
 * widget used, a page at a time. */

const KIND_WORD: Record<string, string> = {
  open: "Open issues",
  past_sla: "Open issues past their SLA",
  opened: "Issues first seen in the period",
  fixed: "Issues fixed in the period",
};

export function MetricIssuesScreen({ query }: { query: string }) {
  const params = new URLSearchParams(query);
  const label = params.get("label");
  const expected = params.get("n");
  params.delete("label");
  params.delete("n");
  const base = params.toString();
  const [rows, setRows] = useState<MetricIssue[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const page = useCallback(
    async (after: string | null) => {
      const p = new URLSearchParams(base);
      if (after) p.set("after", after);
      try {
        const r = await getMetricIssues(p);
        setRows((prev) => (after ? [...prev, ...r.rows] : r.rows));
        setNext(r.next);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "Could not load these issues.");
      } finally {
        setLoaded(true);
      }
    },
    [base],
  );
  useEffect(() => {
    void page(null);
  }, [page]);

  const kind = params.get("kind") ?? "open";
  const title = label || KIND_WORD[kind] || "Issues";
  const scope = [
    params.get("band") && `priority ${params.get("band")}`,
    params.get("older_than") && `older than ${params.get("older_than")} days`,
    params.get("from") && `from ${params.get("from")} to ${params.get("to")}`,
    params.get("tag") && `tag “${params.get("tag")}”`,
    params.getAll("portfolio").length > 0 && "the widget's portfolios",
    params.getAll("project").length > 0 && "the widget's projects",
  ].filter(Boolean);

  return (
    <div className="dash">
      <span className="eyebrow">Behind the number</span>
      <h1>{title}</h1>
      <p className="dash-muted">
        {KIND_WORD[kind] ?? "Issues"}
        {scope.length ? `, ${scope.join(", ")}` : ""}. <Link href="/app/dashboards">Back to dashboards</Link>
      </p>
      {error && <p role="alert" className="dash-error">{error}</p>}
      {!loaded && <p role="status">Loading…</p>}
      {loaded && !error && (
        <div className="dash-table-wrap">
          <table className="dash-table">
            <caption>
              {next ? `Showing ${rows.length}` : `${rows.length} issue${rows.length === 1 ? "" : "s"}`}
              {next && expected ? ` of ${Number(expected).toLocaleString()}` : next ? ", more below" : ""}
            </caption>
            <thead>
              <tr>
                <th scope="col">Issue</th>
                <th scope="col">Project</th>
                <th scope="col">Priority</th>
                <th scope="col">Severity</th>
                <th scope="col">First seen</th>
                <th scope="col">{kind === "fixed" ? "Fixed" : "Assignee"}</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr><td colSpan={6} className="dash-muted">No issues match.</td></tr>
              )}
              {rows.map((r) => (
                <tr key={r.id}>
                  <th scope="row">
                    <Link href={`/app/projects/${encodeURIComponent(r.project_id)}/issues/${encodeURIComponent(r.id)}`}>{r.title}</Link>
                  </th>
                  <td>{r.project}</td>
                  <td>{r.band ?? "—"}</td>
                  <td>{r.severity}</td>
                  <td>{r.first_seen_at?.slice(0, 10) ?? "—"}</td>
                  <td>{kind === "fixed" ? r.fixed_at?.slice(0, 10) ?? "—" : r.assignee_name ?? r.assignee ?? "Unassigned"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {next && (
            <button type="button" className="ds-button" onClick={() => void page(next)}>Show more</button>
          )}
        </div>
      )}
    </div>
  );
}
