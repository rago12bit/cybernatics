"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, getChecklist, getEngagement, setChecklistItem } from "@/lib/api";
import type { ChecklistItem, ChecklistResult, ChecklistSummary, EngagementDetail } from "@/lib/types";
import "./engagement.css";

/** An engagement's OWASP checklist (plan §43.1): every test or requirement with its result and a
 * note, grouped as OWASP groups them. Each change is audit-logged on the server. */

const RESULTS: [ChecklistResult | "", string][] = [
  ["", "Not started"],
  ["in_progress", "In progress"],
  ["pass", "Pass"],
  ["fail", "Fail"],
  ["not_applicable", "Not applicable"],
];
type Filter = "all" | "open" | "fail";

export function ChecklistScreen({ id }: { id: string }) {
  const [eng, setEng] = useState<EngagementDetail | null>(null);
  const [summary, setSummary] = useState<ChecklistSummary | null>(null);
  const [items, setItems] = useState<ChecklistItem[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const load = useCallback(() => {
    getEngagement(id).then(setEng, () => setEng(null));
    getChecklist(id).then(
      (c) => { setSummary(c.summary); setItems(c.items); },
      (e) => setError(e instanceof ApiError ? e.message : "Could not load the checklist."),
    );
  }, [id]);
  useEffect(load, [load]);

  async function save(item: ChecklistItem, status: ChecklistResult | null, note: string | null) {
    setError(null);
    try {
      setSummary(await setChecklistItem(id, item.id, status, note ?? undefined));
      setItems((xs) => xs.map((x) => (x.id === item.id ? { ...x, status, note } : x)));
      setSaved(`${item.id} saved.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save.");
    }
  }

  const groups = useMemo(() => {
    const shown = items.filter((i) => filter === "all" || (filter === "fail" ? i.status === "fail" : !i.status || i.status === "in_progress"));
    const out = new Map<string, ChecklistItem[]>();
    for (const i of shown) out.set(i.group, [...(out.get(i.group) ?? []), i]);
    return [...out.entries()];
  }, [items, filter]);

  if (error && !summary) return <p role="alert" className="ds-eng-error">{error}</p>;
  if (!summary) return <p role="status">Loading the checklist…</p>;
  const locked = eng?.status === "closed";

  return (
    <div className="ds-eng ds-eng-wide">
      <p><Link href={`/app/engagements/${id}`}>← {eng?.name ?? "Engagement"}</Link></p>
      <h1 className="ds-eng-title">{summary.name}</h1>
      <p className="ds-eng-verdict">
        {summary.done} of {summary.total} done: {summary.pass} passed, {summary.fail} failed, {summary.not_applicable} not applicable
        {summary.in_progress ? `, ${summary.in_progress} in progress` : ""}.
      </p>
      <progress max={summary.total} value={summary.done} aria-label="Checklist progress" className="ds-eng-progress" />
      {locked && <p className="ds-eng-meta">The engagement is closed: reopen it to change results.</p>}
      {error && <p role="alert" className="ds-eng-error">{error}</p>}
      <p role="status" className="ds-eng-sr">{saved}</p>
      <div className="ds-eng-filter" role="group" aria-label="Show">
        {(["all", "open", "fail"] as Filter[]).map((f) => (
          <button key={f} type="button" className={filter === f ? "ds-chip active" : "ds-chip"} aria-pressed={filter === f} onClick={() => setFilter(f)}>
            {f === "all" ? "All" : f === "open" ? "Not done" : "Failed"}
          </button>
        ))}
      </div>
      {groups.map(([group, xs]) => (
        <section key={group} className="ds-eng-check-group" aria-label={group}>
          <h2>{group}</h2>
          <ul className="ds-eng-checks">
            {xs.map((i) => (
              <li key={i.id} className={i.status ? `ds-eng-check-${i.status}` : undefined}>
                <div className="ds-eng-check-text">
                  <code>{i.id}</code>{" "}
                  {i.reference ? <a href={i.reference} target="_blank" rel="noopener noreferrer">{i.title}</a> : i.title}
                  {i.level && <span className="ds-eng-meta"> · L{i.level}</span>}
                  {i.cwe && <span className="ds-eng-meta"> · {i.cwe}</span>}
                </div>
                <select aria-label={`${i.id} result`} value={i.status ?? ""} disabled={locked}
                  onChange={(e) => save(i, (e.target.value || null) as ChecklistResult | null, i.note)}>
                  {RESULTS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
                </select>
                <input aria-label={`${i.id} note`} className="ds-eng-check-note" defaultValue={i.note ?? ""} placeholder="Note" disabled={locked || !i.status}
                  onBlur={(e) => e.target.value !== (i.note ?? "") && save(i, i.status, e.target.value || null)} />
              </li>
            ))}
          </ul>
        </section>
      ))}
      <p className="ds-eng-meta">Checklist content: {summary.name}, {summary.attribution}.</p>
    </div>
  );
}
