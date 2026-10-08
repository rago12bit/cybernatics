"use client";

import { useEffect, useId, useState } from "react";
import { ApiError, listChecklists } from "@/lib/api";
import { localDay } from "@/lib/format";
import type { ChecklistCatalogue, Engagement, EngagementInput } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./engagement.css";

/** Plan §43.1: an assessment's scope, people, dates and checklist. Used to create one and to edit
 * one. People are names (or API token names) until user accounts exist. */

type FieldError = { field: string; message: string };

const lines = (text: string) => text.split(/\n|,/).map((x) => x.trim()).filter(Boolean);
const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : "");

export function EngagementForm({
  initial,
  submitLabel,
  onSubmit,
  onCancel,
}: {
  initial?: Engagement;
  submitLabel: string;
  onSubmit: (body: EngagementInput) => Promise<void>;
  onCancel?: () => void;
}) {
  const id = useId();
  const [catalogue, setCatalogue] = useState<ChecklistCatalogue[]>([]);
  const [name, setName] = useState(initial?.name ?? "");
  const [type, setType] = useState(initial?.engagement_type ?? "pentest");
  const [targets, setTargets] = useState((initial?.scope_targets ?? []).join("\n"));
  const [routes, setRoutes] = useState((initial?.scope_routes ?? []).join("\n"));
  const [out, setOut] = useState(initial?.out_of_scope ?? "");
  const [lead, setLead] = useState(initial?.lead ?? "");
  const [testers, setTesters] = useState((initial?.testers ?? []).join(", "));
  const [starts, setStarts] = useState(day(initial?.starts_at) || localDay());
  const [ends, setEnds] = useState(day(initial?.ends_at));
  const [checklist, setChecklist] = useState(initial?.checklist?.id ?? "");
  const [fieldError, setFieldError] = useState<FieldError | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    listChecklists().then(setCatalogue, () => setCatalogue([]));
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setFieldError(null);
    setError(null);
    if (!name.trim()) return setFieldError({ field: "name", message: "Name the engagement." });
    setSaving(true);
    try {
      await onSubmit({
        name: name.trim(),
        ...(initial ? {} : { engagement_type: type }),
        scope_targets: lines(targets),
        scope_routes: lines(routes),
        out_of_scope: out.trim() || null,
        lead: lead.trim() || null,
        testers: lines(testers),
        starts_at: starts ? `${starts}T00:00:00Z` : null,
        ends_at: ends ? `${ends}T00:00:00Z` : null,
        checklist: checklist || null,
      });
    } catch (err) {
      const d = err instanceof ApiError ? (err.data as Partial<FieldError> | undefined) : undefined;
      if (d?.field && d.message) setFieldError({ field: d.field, message: d.message });
      else setError(err instanceof ApiError ? err.message : "Could not save.");
    } finally {
      setSaving(false);
    }
  }

  const fid = (f: string) => `${id}-${f}`;
  const errFor = (f: string) =>
    fieldError?.field === f ? <p id={`${fid(f)}-err`} className="ds-eng-error">{fieldError.message}</p> : null;
  const aria = (f: string) => ({
    "aria-invalid": fieldError?.field === f || undefined,
    "aria-describedby": fieldError?.field === f ? `${fid(f)}-err` : undefined,
  });

  return (
    <form className="ds-eng-form" onSubmit={submit} noValidate>
      {error && <p role="alert" className="ds-eng-error">{error}</p>}
      {fieldError && <p role="alert" className="ds-eng-sr">{fieldError.message}</p>}
      <div className="ds-eng-row">
        <label htmlFor={fid("name")}>Name</label>
        <input id={fid("name")} value={name} onChange={(e) => setName(e.target.value)} placeholder="Q3 external pentest" maxLength={300} {...aria("name")} />
        {errFor("name")}
      </div>
      {!initial && (
        <div className="ds-eng-row">
          <label htmlFor={fid("type")}>Kind</label>
          <select id={fid("type")} value={type} onChange={(e) => setType(e.target.value)}>
            <option value="pentest">Penetration test</option>
            <option value="audit">Audit</option>
            <option value="assessment">Assessment</option>
          </select>
        </div>
      )}
      <div className="ds-eng-grid">
        <div className="ds-eng-row">
          <label htmlFor={fid("targets")}>In scope: targets</label>
          <textarea id={fid("targets")} rows={2} value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="api.acme.example" {...aria("scope_targets")} />
          {errFor("scope_targets")}
        </div>
        <div className="ds-eng-row">
          <label htmlFor={fid("routes")}>In scope: routes</label>
          <textarea id={fid("routes")} rows={2} value={routes} onChange={(e) => setRoutes(e.target.value)} placeholder="/v2/" {...aria("scope_routes")} />
          {errFor("scope_routes")}
        </div>
      </div>
      <div className="ds-eng-row">
        <label htmlFor={fid("out")}>Out of scope</label>
        <input id={fid("out")} value={out} onChange={(e) => setOut(e.target.value)} placeholder="Admin panel, staging" {...aria("out_of_scope")} />
        {errFor("out_of_scope")}
      </div>
      <div className="ds-eng-grid">
        <div className="ds-eng-row">
          <label htmlFor={fid("lead")}>Lead</label>
          <input id={fid("lead")} value={lead} onChange={(e) => setLead(e.target.value)} placeholder="Priya N." {...aria("lead")} />
          {errFor("lead")}
        </div>
        <div className="ds-eng-row">
          <label htmlFor={fid("testers")}>Testers (comma-separated)</label>
          <input id={fid("testers")} value={testers} onChange={(e) => setTesters(e.target.value)} placeholder="Arjun K., Meera S." {...aria("testers")} />
          {errFor("testers")}
        </div>
      </div>
      <div className="ds-eng-grid">
        <div className="ds-eng-row">
          <label htmlFor={fid("starts")}>Starts</label>
          <input id={fid("starts")} type="date" value={starts} onChange={(e) => setStarts(e.target.value)} {...aria("starts_at")} />
          {errFor("starts_at")}
        </div>
        <div className="ds-eng-row">
          <label htmlFor={fid("ends")}>Ends</label>
          <input id={fid("ends")} type="date" value={ends} onChange={(e) => setEnds(e.target.value)} min={starts || undefined} {...aria("ends_at")} />
          {errFor("ends_at")}
        </div>
      </div>
      <div className="ds-eng-row">
        <label htmlFor={fid("checklist")}>Checklist</label>
        <select id={fid("checklist")} value={checklist} onChange={(e) => setChecklist(e.target.value)} {...aria("checklist")}>
          <option value="">None</option>
          {catalogue.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.items} items)</option>)}
        </select>
        {errFor("checklist")}
      </div>
      <div className="ds-eng-actions">
        {onCancel && <Button type="button" onClick={onCancel}>Cancel</Button>}
        <Button variant="primary" type="submit" disabled={saving}>{saving ? "Saving…" : submitLabel}</Button>
      </div>
    </form>
  );
}
