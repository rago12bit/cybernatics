"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useMemo, useState } from "react";
import { ApiError, getPriority, previewPriority, savePriority } from "@/lib/api";
import type { PriorityBand, PriorityContext, PriorityOverview, PriorityPreview, PriorityPreviewRow, PriorityRecompute } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./priority-screen.css";
import { formatDate, formatDateTime } from "@/lib/format";

/** A project's priority weights (plan §44.3, §55.7, Week 63): its business context, a slider per
 * factor, and -- before anything is saved -- the top 50 issues under the new weights next to where
 * they are now. Saving re-ranks every issue in the background; the page shows the progress, and the
 * server refuses another change until it finishes. */

const BAND_ORDER: PriorityBand[] = ["P1", "P2", "P3", "P4"];
const POLL_MS = 1500;
type FieldError = { field: string; message: string };

const weightWord = (w: number) => (w === 0 ? "Off" : `×${w.toFixed(2).replace(/\.?0+$/, "")}`);
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export function recomputeSentence(r: PriorityRecompute | null): string | null {
  if (!r) return null;
  if (r.status === "pending") return "Waiting to apply the new weights to every issue…";
  if (r.status === "running") return `Applying the new weights: ${r.processed.toLocaleString()} of ${r.total.toLocaleString()} issues…`;
  if (r.status === "done") return `Applied to ${r.processed.toLocaleString()} issue${r.processed === 1 ? "" : "s"}; ${r.changed.toLocaleString()} changed band.`;
  if (r.status === "failed") return `Applying the weights stopped: ${r.error ?? "unknown error"}. Save again to retry.`;
  return "Replaced by a later change before it finished.";
}

function movement(r: PriorityPreviewRow): { word: string; cls: string } {
  if (!r.before || r.before.rank == null) return { word: "new to the top", cls: "up" };
  if (!r.after || r.after.rank == null) return { word: "", cls: "" };
  const d = r.before.rank - r.after.rank;
  if (d > 0) return { word: `▲ ${d}`, cls: "up" };
  if (d < 0) return { word: `▼ ${-d}`, cls: "down" };
  return { word: "—", cls: "same" };
}

export function PriorityScreen({ assetId }: { assetId: string }) {
  const id = useId();
  const [data, setData] = useState<PriorityOverview | null>(null);
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [context, setContext] = useState<PriorityContext>({ internet_facing: null, data_sensitivity: null, criticality: null });
  const [note, setNote] = useState("");
  const [preview, setPreview] = useState<PriorityPreview | null>(null);
  const [previewed, setPreviewed] = useState<string | null>(null); // the draft the preview is of
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<FieldError | null>(null);
  const [busy, setBusy] = useState(false);

  const show = useCallback((o: PriorityOverview, resetDraft: boolean) => {
    setData(o);
    if (resetDraft) {
      setWeights(o.weights);
      setContext(o.context);
    }
  }, []);
  const load = useCallback(
    (resetDraft = true) =>
      getPriority(assetId).then((o) => show(o, resetDraft), (e) => setError(e instanceof ApiError ? e.message : "Could not load the priority weights.")),
    [assetId, show],
  );
  useEffect(() => {
    load();
  }, [load]);

  // While the server is applying a change, follow its progress.
  useEffect(() => {
    if (!data?.locked) return;
    const t = setTimeout(() => load(false), POLL_MS);
    return () => clearTimeout(t);
  }, [data, load]);

  const draft = useMemo(() => JSON.stringify({ weights, context }), [weights, context]);
  const previewIsCurrent = preview !== null && previewed === draft;
  const unchanged = data !== null && same(weights, data.weights) && same(context, data.context) && data.version > 0;

  function fail(err: unknown, fallback: string) {
    const d = err instanceof ApiError ? (err.data as Partial<FieldError> | undefined) : undefined;
    if (d?.field && d.message) setFieldError({ field: d.field, message: d.message });
    else setError(err instanceof ApiError ? err.message : fallback);
  }

  async function runPreview() {
    setError(null);
    setFieldError(null);
    setBusy(true);
    try {
      setPreview(await previewPriority(assetId, { weights, context }));
      setPreviewed(draft);
    } catch (err) {
      fail(err, "Could not preview.");
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setError(null);
    setFieldError(null);
    setBusy(true);
    try {
      show(await savePriority(assetId, { weights, context, note: note.trim() || undefined }), true);
      setNote("");
      setPreview(null);
      setPreviewed(null);
    } catch (err) {
      fail(err, "Could not save.");
      load(false);
    } finally {
      setBusy(false);
    }
  }

  if (error && !data) return <p role="alert" className="ds-prio-error">{error}</p>;
  if (!data) return <p role="status">Loading the priority weights…</p>;

  const fid = (f: string) => `${id}-${f.replace(/\./g, "-")}`;
  const errorFor = (f: string) =>
    fieldError?.field === f ? <p id={`${fid(f)}-err`} className="ds-prio-error">{fieldError.message}</p> : null;
  const aria = (f: string) => ({
    "aria-invalid": fieldError?.field === f || undefined,
    "aria-describedby": fieldError?.field === f ? `${fid(f)}-err` : undefined,
  });
  const setCtx = (k: keyof PriorityContext, v: string) =>
    setContext((c) => ({ ...c, [k]: k === "internet_facing" ? (v === "" ? null : v === "yes") : v || null }));
  const status = recomputeSentence(data.recompute);
  const latest = data.history[0];

  return (
    <div className="ds-prio">
      <h1 className="ds-prio-title">Priority</h1>
      <p className="ds-prio-verdict">
        {data.version === 0
          ? "Issues are ranked by the standard risk score. Adjust the weights below to rank them for this project."
          : `Ranked by version ${data.version}, saved ${latest ? `by ${latest.changed_by ?? "someone"} on ${formatDate(latest.changed_at)}` : ""}.`}
      </p>
      {status && (
        <p role="status" className={`ds-prio-status ds-prio-status-${data.recompute?.status}`}>
          {status}
          {data.locked && data.recompute && data.recompute.total > 0 && (
            <progress max={data.recompute.total} value={data.recompute.processed} aria-label="Issues re-ranked" />
          )}
        </p>
      )}

      {fieldError && <p role="alert" className="ds-prio-sr">{fieldError.message}</p>}
      {error && <p role="alert" className="ds-prio-error">{error}</p>}

      <fieldset className="ds-prio-context">
        <legend>Business context</legend>
        <p className="ds-prio-help">
          The same issue matters less in an internal wiki than in a payments service. Until you say otherwise, a project is treated as
          internet-facing, handling restricted data and critical, so these answers can only lower its scores. They apply to every
          issue alike: they move bands and SLA deadlines, not the order.
        </p>
        <div className="ds-prio-context-grid">
          <label htmlFor={fid("context.internet_facing")}>Internet-facing</label>
          <select id={fid("context.internet_facing")} value={context.internet_facing === null ? "" : context.internet_facing ? "yes" : "no"}
            onChange={(e) => setCtx("internet_facing", e.target.value)} {...aria("context.internet_facing")}>
            <option value="">Not set</option>
            <option value="yes">Yes: reachable from the internet</option>
            <option value="no">No: internal only</option>
          </select>
          <label htmlFor={fid("context.data_sensitivity")}>Data sensitivity</label>
          <select id={fid("context.data_sensitivity")} value={context.data_sensitivity ?? ""} onChange={(e) => setCtx("data_sensitivity", e.target.value)} {...aria("context.data_sensitivity")}>
            <option value="">Not set</option>
            {data.sensitivity_levels.map((l) => <option key={l} value={l}>{cap(l)}</option>)}
          </select>
          <label htmlFor={fid("context.criticality")}>Business criticality</label>
          <select id={fid("context.criticality")} value={context.criticality ?? ""} onChange={(e) => setCtx("criticality", e.target.value)} {...aria("context.criticality")}>
            <option value="">Not set</option>
            {data.criticality_levels.map((l) => <option key={l} value={l}>{cap(l)}</option>)}
          </select>
        </div>
        {errorFor("context.internet_facing")}
        {errorFor("context.data_sensitivity")}
        {errorFor("context.criticality")}
        {errorFor("context")}
      </fieldset>

      <fieldset className="ds-prio-weights">
        <legend>Weights</legend>
        <p className="ds-prio-help">
          1 is the factor as designed, 0 turns it off, 2 doubles its pull either way.
          {data.version === 0 && " Taint, runtime and path context start off, as in the standard score."}
        </p>
        {data.factors.map((f) => (
          <div key={f.key} className="ds-prio-weight">
            <label htmlFor={fid(`weights.${f.key}`)}>
              <span className="ds-prio-weight-name">{f.label}</span>
              <span className="ds-prio-weight-desc" id={fid(`weights.${f.key}-d`)}>{f.description}</span>
            </label>
            <input id={fid(`weights.${f.key}`)} type="range" min={0} max={data.max_weight} step={0.25}
              value={weights[f.key] ?? 1} aria-invalid={fieldError?.field === `weights.${f.key}` || undefined}
              aria-describedby={fieldError?.field === `weights.${f.key}` ? `${fid(`weights.${f.key}`)}-err ${fid(`weights.${f.key}-d`)}` : fid(`weights.${f.key}-d`)}
              aria-valuetext={weightWord(weights[f.key] ?? 1)}
              onChange={(e) => setWeights((w) => ({ ...w, [f.key]: Number(e.target.value) }))} />
            <output htmlFor={fid(`weights.${f.key}`)} className="ds-prio-weight-value">{weightWord(weights[f.key] ?? 1)}</output>
            {errorFor(`weights.${f.key}`)}
          </div>
        ))}
        {errorFor("weights")}
      </fieldset>

      <div className="ds-prio-actions">
        <Button type="button" onClick={runPreview} disabled={busy}>Preview the top 50</Button>
        <Button type="button" onClick={() => setWeights(data.starter)} disabled={busy}>Every factor at 1</Button>
        <Button type="button" onClick={() => { setWeights(data.weights); setContext(data.context); }} disabled={busy}>Undo changes</Button>
      </div>

      {preview && (
        <section className="ds-prio-preview" aria-labelledby={`${id}-pv`}>
          <h2 id={`${id}-pv`}>Before and after</h2>
          {!previewIsCurrent && <p className="ds-prio-help">The weights changed since this preview. Preview again before saving.</p>}
          <p>
            {preview.open_issues === 0
              ? "No open issues to rank yet."
              : `${preview.moved} of the top ${preview.top.length} move under these weights${preview.dropped.length ? `, and ${preview.dropped.length} leave it` : ""}.`}
          </p>
          <table className="ds-prio-bands">
            <caption>Open issues by band</caption>
            <thead><tr><th scope="col">Band</th><th scope="col">Now</th><th scope="col">With these weights</th></tr></thead>
            <tbody>
              {BAND_ORDER.map((b) => (
                <tr key={b}><th scope="row">{b}</th><td>{preview.bands_before[b]}</td><td>{preview.bands_after[b]}</td></tr>
              ))}
            </tbody>
          </table>
          {preview.top.length > 0 && (
            <div className="ds-prio-scroll">
              <table className="ds-prio-top">
                <caption>The top {preview.top.length}, with these weights</caption>
                <thead>
                  <tr><th scope="col">Rank</th><th scope="col">Moved</th><th scope="col">Issue</th><th scope="col">Score</th><th scope="col">Band</th></tr>
                </thead>
                <tbody>
                  {preview.top.map((r) => {
                    const m = movement(r);
                    return (
                      <tr key={r.issue_id} className={m.cls === "same" ? undefined : "ds-prio-moved"}>
                        <td>{r.after?.rank}</td>
                        <td className={`ds-prio-move-${m.cls}`}>{m.word}{r.before?.rank != null && m.cls !== "same" && <span className="ds-prio-was"> (was {r.before.rank})</span>}</td>
                        <td><Link href={`/app/projects/${assetId}/issues/${r.issue_id}`}>{r.title}</Link> <span className="ds-prio-path">{r.severity.toLowerCase()} · {r.path}</span></td>
                        <td>{r.before?.score ?? "—"} → {r.after?.score ?? "—"}</td>
                        <td>{r.before?.band ?? "—"}{r.before?.band !== r.after?.band ? ` → ${r.after?.band ?? "—"}` : ""}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {preview.dropped.length > 0 && (
            <>
              <h3>Leaving the top {preview.top.length}</h3>
              <ul className="ds-prio-dropped">
                {preview.dropped.map((r) => (
                  <li key={r.issue_id}>
                    <Link href={`/app/projects/${assetId}/issues/${r.issue_id}`}>{r.title}</Link>: rank {r.before?.rank} → {r.after?.rank}, score {r.before?.score} → {r.after?.score}
                  </li>
                ))}
              </ul>
            </>
          )}

          <div className="ds-prio-row">
            <label htmlFor={fid("note")}>Why (optional, kept in the history)</label>
            <input id={fid("note")} value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
          </div>
          <div className="ds-prio-actions">
            <Button variant="primary" type="button" onClick={save} disabled={busy || !previewIsCurrent || data.locked || unchanged}>
              {data.locked ? "Wait for the last change to finish" : busy ? "Saving…" : "Save and re-rank every issue"}
            </Button>
            {unchanged && <span className="ds-prio-help">These are the weights in force.</span>}
          </div>
        </section>
      )}

      {data.history.length > 0 && (
        <div className="ds-prio-scroll">
        <table className="ds-prio-history">
          <caption>History</caption>
          <thead><tr><th scope="col">Version</th><th scope="col">When</th><th scope="col">By</th><th scope="col">Changed from the starter</th><th scope="col">Applied</th><th scope="col">Why</th></tr></thead>
          <tbody>
            {data.history.map((h) => {
              const changed = data.factors.filter((f) => h.weights[f.key] !== data.starter[f.key]).map((f) => `${f.label} ${weightWord(h.weights[f.key] ?? 1)}`);
              const ctx = [
                h.context.internet_facing === null ? null : h.context.internet_facing ? "internet-facing" : "internal",
                h.context.data_sensitivity && `${h.context.data_sensitivity} data`,
                h.context.criticality && `${h.context.criticality} criticality`,
              ].filter(Boolean);
              return (
                <tr key={h.version}>
                  <td>{h.version}</td>
                  <td>{formatDateTime(h.changed_at)}</td>
                  <td>{h.changed_by ?? "—"}</td>
                  <td>{[...changed, ...ctx].join(", ") || "Nothing"}</td>
                  <td>{h.recompute.status === "done" ? `${h.recompute.processed} issues` : h.recompute.status}</td>
                  <td>{h.note ?? ""}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        </div>
      )}
    </div>
  );
}
