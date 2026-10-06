"use client";

import Link from "next/link";
import { Fragment, useCallback, useEffect, useId, useMemo, useState } from "react";
import { ApiError, getAsvs, setAsvsStatus } from "@/lib/api";
import type { AsvsBenchmark, AsvsRequirement, AsvsStatus } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./compliance.css";

/** A project's ASVS 4.0.3 checklist (plan §47): every requirement up to a level, with a status and
 * the evidence for it. Only a person marks a requirement met; Bulwark shows open Issues of its CWE
 * and assessment results as evidence, and never treats the absence of findings as proof. */

export const ASVS_STATUS: Record<AsvsStatus, string> = {
  met: "Met",
  not_met: "Not met",
  not_applicable: "Not applicable",
  issues_open: "Issues open",
  tested: "Passed a test",
  not_assessed: "Not assessed",
};
const COUNTED: Record<AsvsStatus, string> = {
  met: "met", not_met: "not met", not_applicable: "not applicable", issues_open: "with open Issues",
  tested: "passed a test", not_assessed: "not assessed",
};
const ORDER: AsvsStatus[] = ["not_met", "issues_open", "not_assessed", "tested", "met", "not_applicable"];

function Editor({ assetId, r, onSaved }: { assetId: string; r: AsvsRequirement; onSaved: () => void }) {
  const id = useId();
  const [status, setStatus] = useState<"" | "met" | "not_met" | "not_applicable">(r.source === "person" ? (r.status as "met" | "not_met" | "not_applicable") : "");
  const [note, setNote] = useState(r.note);
  const [links, setLinks] = useState(r.links.join("\n"));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function save() {
    setBusy(true);
    setError(null);
    try {
      await setAsvsStatus(assetId, r.id, {
        status: status || null, note,
        links: links.split("\n").map((l) => l.trim()).filter(Boolean),
      });
      onSaved();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not save.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="ds-cmp-editor">
      <label htmlFor={`${id}-s`}>Your status</label>
      <select id={`${id}-s`} value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
        <option value="">None: show what the evidence says</option>
        <option value="met">Met</option>
        <option value="not_met">Not met</option>
        <option value="not_applicable">Not applicable</option>
      </select>
      <label htmlFor={`${id}-n`}>Note {status === "met" || status === "not_applicable" ? "(required)" : ""}</label>
      <textarea id={`${id}-n`} rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
      <label htmlFor={`${id}-l`}>Evidence links, one per line (https:// or /app/…)</label>
      <textarea id={`${id}-l`} rows={2} value={links} onChange={(e) => setLinks(e.target.value)} />
      <div className="ds-cmp-actions">
        <Button variant="primary" disabled={busy} onClick={save}>Save</Button>
      </div>
      {error && <p role="alert" className="ds-cmp-error">{error}</p>}
    </div>
  );
}

export function AsvsScreen({ assetId }: { assetId: string }) {
  const fid = useId();
  const [level, setLevel] = useState(2);
  const [b, setB] = useState<AsvsBenchmark | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<AsvsStatus | "all">("all");
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(() => {
    getAsvs(assetId, level).then(setB, (e) => setError(e instanceof ApiError && e.status === 404 ? "Project not found." : "Could not load the checklist."));
  }, [assetId, level]);
  useEffect(load, [load]);

  const rows = useMemo(() => (b ? b.requirements.filter((r) => filter === "all" || r.status === filter) : []), [b, filter]);
  if (!b) return <div className="ds-cmp">{error ? <p role="alert" className="ds-cmp-error">{error}</p> : <p>Loading…</p>}</div>;
  return (
    <div className="ds-cmp">
      <header>
        <h1 className="ds-cmp-title">ASVS for {b.project}</h1>
        <p className="ds-cmp-lede">{b.disclaimer}</p>
        <p className="ds-cmp-meta">
          {b.framework.name}, © OWASP Foundation, CC BY-SA 4.0 · <a href={b.framework.source.url} rel="noopener noreferrer" target="_blank">source</a>
        </p>
        <div className="ds-cmp-filters" role="group" aria-label="Level and status">
          <label htmlFor={`${fid}-lvl`}>Level</label>
          <select id={`${fid}-lvl`} value={level} onChange={(e) => setLevel(Number(e.target.value))}>
            <option value={1}>1</option><option value={2}>2</option><option value={3}>3</option>
          </select>
          <label htmlFor={`${fid}-st`}>Show</label>
          <select id={`${fid}-st`} value={filter} onChange={(e) => setFilter(e.target.value as AsvsStatus | "all")}>
            <option value="all">All {b.requirements.length} requirements</option>
            {ORDER.filter((s) => b.counts[s]).map((s) => <option key={s} value={s}>{ASVS_STATUS[s]} ({b.counts[s]})</option>)}
          </select>
        </div>
        <ul className="ds-cmp-counts" aria-label="Requirements by status">
          {ORDER.filter((s) => b.counts[s]).map((s) => (
            <li key={s} className={`ds-cmp-st-${s}`}><strong>{b.counts[s]}</strong> {COUNTED[s]}</li>
          ))}
        </ul>
      </header>

      <table className="ds-cmp-table">
        <thead>
          <tr><th scope="col">Requirement</th><th scope="col">Status</th><th scope="col">Evidence</th><th scope="col"><span className="ds-cmp-sr">Edit</span></th></tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <Fragment key={r.id}>
            <tr>
              <th scope="row" data-label="Requirement">
                <span className="ds-cmp-id">{r.id}</span> <span className="ds-cmp-wrap">{r.title}</span>
                <span className="ds-cmp-meta"> · L{r.level}{r.cwe ? ` · ${r.cwe}` : ""}</span>
              </th>
              <td data-label="Status" className={`ds-cmp-st-${r.status}`}>
                {ASVS_STATUS[r.status]}
                {r.conflict && <span className="ds-cmp-bad"> · contradicted by the evidence</span>}
                {r.set_by && <span className="ds-cmp-meta"> · {r.set_by}</span>}
              </td>
              <td data-label="Evidence">
                {r.issues > 0 && <Link href={`/app/projects/${assetId}/issues/${r.issue_ids[0]}`}>{r.issues} open Issue{r.issues === 1 ? "" : "s"}</Link>}
                {r.assessment && (
                  <span className="ds-cmp-meta">{r.issues ? " · " : ""}{r.assessment.status === "pass" ? "passed" : r.assessment.status === "fail" ? "failed" : "not applicable"} in <Link href={`/app/engagements/${r.assessment.engagement_id}`}>{r.assessment.engagement}</Link></span>
                )}
                {r.note && <span className="ds-cmp-wrap ds-cmp-meta">{r.issues || r.assessment ? " · " : ""}{r.note}</span>}
                {r.links.map((l) => (
                  <span key={l}> · <a href={l} rel="noopener noreferrer nofollow" target={l.startsWith("/") ? undefined : "_blank"}>link</a></span>
                ))}
                {!r.issues && !r.assessment && !r.note && !r.links.length && <span className="ds-cmp-meta">—</span>}
              </td>
              <td data-label="Edit">
                <Button onClick={() => setOpen(open === r.id ? null : r.id)} aria-expanded={open === r.id}>{open === r.id ? "Close" : "Set"}</Button>
              </td>
            </tr>
            {open === r.id && (
              <tr className="ds-cmp-editor-row">
                <td colSpan={4}><Editor assetId={assetId} r={r} onSaved={() => { setOpen(null); load(); }} /></td>
              </tr>
            )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}
