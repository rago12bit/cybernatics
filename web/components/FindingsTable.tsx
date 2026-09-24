"use client";

import { useEffect, useState } from "react";
import { getFindings } from "@/lib/api";
import { defaultQuery, locationLabel, pageCount } from "@/lib/format";
import { CATEGORIES, SEVERITIES, TOOLS, type Finding, type FindingsPage, type FindingsQuery, type ScanView, type Severity } from "@/lib/types";
import { SeverityBadge } from "./Badges";
import { FindingDetail } from "./FindingDetail";

export function FindingsTable({ scan, version }: { scan: ScanView; version: number }) {
  const [q, setQ] = useState<FindingsQuery>(defaultQuery());
  const [pathInput, setPathInput] = useState("");
  const [page, setPage] = useState<FindingsPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);

  // Debounce the free-text path filter so typing does not fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(() => setQ((cur) => (cur.path === pathInput ? cur : { ...cur, path: pathInput, page: 0 })), 300);
    return () => clearTimeout(t);
  }, [pathInput]);

  useEffect(() => {
    let cancelled = false;
    getFindings(scan.id, q).then(
      (p) => { if (!cancelled) { setPage(p); setError(null); } },
      (e) => { if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load findings"); },
    );
    return () => { cancelled = true; };
  }, [scan.id, q, version]);

  const update = (patch: Partial<FindingsQuery>) => setQ((cur) => ({ ...cur, ...patch, page: patch.page ?? 0 }));
  const toggleSeverity = (s: Severity) =>
    update({ severity: q.severity.includes(s) ? q.severity.filter((x) => x !== s) : [...q.severity, s] });
  const pages = pageCount(page?.total ?? 0);

  return (
    <section aria-labelledby="findings-h" className={selected ? "findings with-detail" : "findings"}>
      <div className="list">
        <h2 id="findings-h">Findings {page && <span className="muted">({page.total})</span>}</h2>

        <div className="filters" role="search" aria-label="Filter findings">
          <div className="chips" role="group" aria-label="Severity">
            {SEVERITIES.map((s) => (
              <button key={s} type="button" className={`filter sev-${s.toLowerCase()}`} aria-pressed={q.severity.includes(s)} onClick={() => toggleSeverity(s)}>{s}</button>
            ))}
          </div>
          <label className="inline">Category
            <select value={q.category} onChange={(e) => update({ category: e.target.value })}>
              <option value="">All</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <label className="inline">Scanner
            <select value={q.tool} onChange={(e) => update({ tool: e.target.value })}>
              <option value="">All</option>
              {TOOLS.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="inline">Sort
            <select value={q.sort} onChange={(e) => update({ sort: e.target.value as FindingsQuery["sort"] })}>
              <option value="severity">Severity</option>
              <option value="path">File path</option>
              <option value="risk">Risk score</option>
            </select>
          </label>
          <label className="inline grow">File
            <input type="search" placeholder="Filter by path…" value={pathInput} onChange={(e) => setPathInput(e.target.value)} />
          </label>
        </div>

        {error && <p className="error" role="alert">{error}</p>}
        {page && page.items.length === 0 && <p className="muted">{page.total === 0 && scan.unique_findings === 0 ? "No findings." : "No findings match these filters."}</p>}
        {page && page.items.length > 0 && (
          <div className="scroll">
            <table className="findings-table">
              <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Scanners</th></tr></thead>
              <tbody>
                {page.items.map((f) => (
                  <tr key={f.id} className={selected?.id === f.id ? "selected" : ""}>
                    <td><SeverityBadge severity={f.scoring.normalized_severity} /></td>
                    <td>
                      <button type="button" className="link row-title" onClick={() => setSelected(f)} aria-pressed={selected?.id === f.id}>{f.title}</button>
                    </td>
                    <td><code className="small">{locationLabel(f)}</code></td>
                    <td>
                      <span title={f.evidence.reported_by.join(", ")}>{f.evidence.agreement_count > 1 ? `${f.evidence.agreement_count} agree` : f.evidence.reported_by[0]}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <nav className="pager" aria-label="Pagination">
          <button type="button" disabled={q.page === 0} onClick={() => setQ({ ...q, page: q.page - 1 })}>← Prev</button>
          <span>Page {q.page + 1} of {pages}</span>
          <button type="button" disabled={q.page + 1 >= pages} onClick={() => setQ({ ...q, page: q.page + 1 })}>Next →</button>
        </nav>
      </div>
      {selected && <FindingDetail finding={selected} scan={scan} onClose={() => setSelected(null)} />}
    </section>
  );
}
