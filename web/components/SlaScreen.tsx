"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import { ApiError, getSla, saveSla } from "@/lib/api";
import { SLA_MARK, SLA_WORD } from "@/lib/sla";
import type { SlaBand, SlaBasis, SlaOverview } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./sla-screen.css";

/** A project's SLA policy (plan §44.1, Week 61): how many days each severity -- or, since Week 63,
 * each priority band -- has to be fixed from first detection, and when it counts as due soon.
 * Starter values are offered, not imposed -- the project has no SLA until someone turns it on and
 * saves. Every save is a new version. */

const BANDS_BY: Record<SlaBasis, readonly string[]> = {
  severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
  priority: ["P1", "P2", "P3", "P4"],
};
type Draft = Record<string, { days: string; warn: string }>;
type FieldError = { field: string; message: string };

const bandName = (b: string) => (b.startsWith("P") ? b : b.charAt(0) + b.slice(1).toLowerCase());

const toDraft = (bands: Record<string, SlaBand>, basis: SlaBasis): Draft =>
  Object.fromEntries(BANDS_BY[basis].map((b) => [b, { days: bands[b]?.days?.toString() ?? "", warn: bands[b]?.days ? String(bands[b]?.warn ?? 0) : "" }]));

function toBands(d: Draft, basis: SlaBasis): Record<string, SlaBand> {
  return Object.fromEntries(
    BANDS_BY[basis].map((b) => {
      const days = d[b]?.days.trim() ?? "";
      const warn = d[b]?.warn.trim() ?? "";
      return [b, { days: days === "" ? null : Number(days), warn: warn === "" ? 0 : Number(warn) }];
    }),
  );
}

export function slaVerdict(o: SlaOverview): string {
  if (!o.enabled) return o.version === 0 ? "No SLA yet. The starter values below are a suggestion." : "The SLA is turned off.";
  const { breached, due_soon } = o.counts;
  if (!breached && !due_soon) return "Every open issue is on track.";
  const parts = [];
  if (breached) parts.push(`${breached} breached`);
  if (due_soon) parts.push(`${due_soon} due soon`);
  return `${parts.join(", ")}.`;
}

export function SlaScreen({ assetId }: { assetId: string }) {
  const id = useId();
  const [data, setData] = useState<SlaOverview | null>(null);
  const [draft, setDraft] = useState<Draft>({});
  const [enabled, setEnabled] = useState(false);
  const [basis, setBasis] = useState<SlaBasis>("severity");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<FieldError | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const show = useCallback((o: SlaOverview) => {
    setData(o);
    setBasis(o.basis);
    setDraft(toDraft(o.bands, o.basis));
    setEnabled(o.enabled || o.version === 0);
  }, []);
  const load = useCallback(() => {
    getSla(assetId).then(show, (e) => setError(e instanceof ApiError ? e.message : "Could not load the SLA."));
  }, [assetId, show]);
  useEffect(load, [load]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setFieldError(null);
    setError(null);
    setSaved(null);
    setSaving(true);
    try {
      const o = await saveSla(assetId, { enabled, basis, bands: toBands(draft, basis), note: note.trim() || undefined });
      show(o);
      setNote("");
      setSaved(`Saved as version ${o.version}.`);
    } catch (err) {
      const d = err instanceof ApiError ? (err.data as Partial<FieldError> | undefined) : undefined;
      if (d?.field && d.message) setFieldError({ field: d.field, message: d.message });
      else setError(err instanceof ApiError ? err.message : "Could not save.");
    } finally {
      setSaving(false);
    }
  }

  if (error && !data) return <p role="alert" className="ds-sla-error">{error}</p>;
  if (!data) return <p role="status">Loading the SLA…</p>;

  const fid = (f: string) => `${id}-${f.replace(/\./g, "-")}`;
  const errorFor = (f: string) =>
    fieldError?.field === f ? <p id={`${fid(f)}-err`} className="ds-sla-field-error">{fieldError.message}</p> : null;
  const aria = (f: string) => ({
    "aria-invalid": fieldError?.field === f || undefined,
    "aria-describedby": fieldError?.field === f ? `${fid(f)}-err` : undefined,
  });
  const starterFor = (b: SlaBasis) => (b === "priority" ? data.starter_by_priority ?? {} : data.starter);
  function switchBasis(b: SlaBasis) {
    if (!data) return;
    setBasis(b);
    setDraft(toDraft(b === data.basis && data.version > 0 ? data.bands : starterFor(b), b));
  }
  const BANDS = BANDS_BY[basis];
  const set = (band: string, key: "days" | "warn", value: string) =>
    setDraft((d) => ({ ...d, [band]: { ...(d[band] ?? { days: "", warn: "" }), [key]: value } }));

  return (
    <div className="ds-sla">
      <h1 className="ds-sla-title">SLA</h1>
      <p className="ds-sla-verdict">{slaVerdict(data)}</p>

      {data.enabled && (
        <table className="ds-sla-counts">
          <caption>Issues by SLA, under version {data.version}</caption>
          <tbody>
            {(["breached", "due_soon", "on_track", "exempt", "met", "missed"] as const).map((k) => (
              <tr key={k}>
                <th scope="row"><span aria-hidden="true">{SLA_MARK[k]} </span>{SLA_WORD[k]}</th>
                <td>{data.counts[k]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data.enabled && (data.counts.breached > 0 || data.counts.due_soon > 0) && (
        <p><Link href={`/app/projects/${assetId}/issues`}>See them in the issues table</Link> (filter by SLA).</p>
      )}

      <form className="ds-sla-form" onSubmit={submit} noValidate aria-labelledby={`${id}-h`}>
        <h2 id={`${id}-h`}>Policy</h2>
        <p className="ds-sla-help">
          The clock starts when an issue is first detected. Re-uploading a report does not restart it.
          An issue marked not a risk, or a risk accepted until a later date, is paused.
        </p>
        {fieldError && <p role="alert" className="ds-sla-sr">{fieldError.message}</p>}
        {error && <p role="alert" className="ds-sla-error">{error}</p>}
        <label className="ds-sla-toggle">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enforce an SLA for this project
        </label>
        <fieldset className="ds-sla-basis">
          <legend>Deadlines by</legend>
          <label><input type="radio" name={`${id}-basis`} checked={basis === "severity"} onChange={() => switchBasis("severity")} /> Severity</label>
          <label><input type="radio" name={`${id}-basis`} checked={basis === "priority"} onChange={() => switchBasis("priority")} /> Priority band</label>
          {basis === "priority" && (
            <p className="ds-sla-help">
              P1 to P4 come from the project&apos;s <Link href={`/app/projects/${assetId}/priority`}>priority weights</Link>, so changing the
              weights or the business context moves deadlines too.
            </p>
          )}
          {errorFor("basis")}
        </fieldset>
        <div className="scroll" tabIndex={0} role="region" aria-label="Deadlines">
          <table className="ds-sla-bands">
            <caption>Deadlines by {basis === "priority" ? "priority band" : "severity"}</caption>
            <thead>
              <tr><th scope="col">{basis === "priority" ? "Band" : "Severity"}</th><th scope="col">Fix within (days)</th><th scope="col">Due soon in the last (days)</th></tr>
            </thead>
            <tbody>
              {BANDS.map((b) => (
                <tr key={b}>
                  <th scope="row">{bandName(b)}</th>
                  <td>
                    <input id={fid(`bands.${b}.days`)} inputMode="numeric" aria-label={`${b.toLowerCase()}: fix within, days`}
                      value={draft[b]?.days ?? ""} placeholder="no deadline" onChange={(e) => set(b, "days", e.target.value)} {...aria(`bands.${b}.days`)} />
                    {errorFor(`bands.${b}.days`)}
                  </td>
                  <td>
                    <input id={fid(`bands.${b}.warn`)} inputMode="numeric" aria-label={`${b.toLowerCase()}: due soon in the last, days`}
                      value={draft[b]?.warn ?? ""} disabled={!draft[b]?.days} onChange={(e) => set(b, "warn", e.target.value)} {...aria(`bands.${b}.warn`)} />
                    {errorFor(`bands.${b}.warn`)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {errorFor("bands")}
        <div className="ds-sla-row">
          <label htmlFor={fid("note")}>Why (optional, kept in the history)</label>
          <input id={fid("note")} value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} />
        </div>
        <div className="ds-sla-actions">
          <Button variant="primary" type="submit" disabled={saving}>{saving ? "Saving…" : "Save policy"}</Button>
          <Button type="button" onClick={() => setDraft(toDraft(starterFor(basis), basis))}>Use starter values</Button>
          {saved && <span role="status">{saved}</span>}
        </div>
      </form>

      {data.history.length > 0 && (
        <div className="scroll" tabIndex={0} role="region" aria-label="Policy history">
          <table className="ds-sla-history">
            <caption>History</caption>
            <thead><tr><th scope="col">Version</th><th scope="col">When</th><th scope="col">By</th><th scope="col">Policy</th><th scope="col">Why</th></tr></thead>
            <tbody>
              {data.history.map((h) => (
                <tr key={h.version}>
                  <td>{h.version}</td>
                  <td>{new Date(h.changed_at).toLocaleString()}</td>
                  <td>{h.changed_by ?? "—"}</td>
                  <td>{h.enabled ? BANDS_BY[h.basis ?? "severity"].filter((b) => h.bands[b]?.days).map((b) => `${bandName(b)} ${h.bands[b]?.days}d`).join(", ") : "Off"}</td>
                  <td>{h.note ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
