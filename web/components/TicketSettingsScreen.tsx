"use client";

import { useEffect, useId, useState } from "react";
import { ApiError, getTicketConfig, saveTicketConfig } from "@/lib/api";
import type { TicketConfigInput, TicketConfigView } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./automation.css";

/** Plan §49: where this project's tickets go, and for each field which side is the source of
 * truth. Status comes from the ticket (mapped here) unless the project hands it to Bulwark; the
 * summary and severity always come from Bulwark; the ticket's assignee is shown, never written. */

const EFFECT_WORD: Record<string, string> = { none: "Nothing", ready_for_retest: "Mark ready for retest" };

export function TicketSettingsScreen({ assetId }: { assetId: string }) {
  const fid = useId();
  const [view, setView] = useState<TicketConfigView | null>(null);
  const [form, setForm] = useState<TicketConfigInput>({ provider: "jira", target: "", status_source: "ticket", status_map: {}, enabled: true });
  const [rows, setRows] = useState<{ status: string; effect: string }[]>([]);
  const [message, setMessage] = useState<{ ok: boolean; text: string; field?: string } | null>(null);

  useEffect(() => {
    getTicketConfig(assetId).then((v) => {
      if (!v?.credentials) return;
      setView(v);
      if (v.configured && v.provider) {
        setForm({ provider: v.provider, target: v.target ?? "", issue_type: v.issue_type, status_source: v.status_source, status_map: v.status_map, enabled: v.enabled });
        setRows(Object.entries(v.status_map).map(([status, effect]) => ({ status, effect })));
      } else if (!v.credentials.jira && v.credentials.github) {
        setForm((f) => ({ ...f, provider: "github" }));
      }
    }, (e) => setMessage({ ok: false, text: e instanceof ApiError ? e.message : "Could not load the settings." }));
  }, [assetId]);

  async function save() {
    setMessage(null);
    const status_map = Object.fromEntries(rows.filter((r) => r.status.trim()).map((r) => [r.status.trim(), r.effect]));
    try {
      const v = await saveTicketConfig(assetId, { ...form, status_map });
      setView(v);
      setMessage({ ok: true, text: "Saved." });
    } catch (e) {
      const field = e instanceof ApiError ? (e.data as { field?: string } | undefined)?.field : undefined;
      setMessage({ ok: false, text: e instanceof ApiError ? e.message : "Could not save.", field });
    }
  }

  if (!view) return message ? <p role="alert" className="ds-au-error">{message.text}</p> : <p role="status">Loading ticket settings…</p>;
  const jira = form.provider === "jira";
  return (
    <form className="ds-au ds-ed ds-np" onSubmit={(e) => { e.preventDefault(); void save(); }}>
      <h1>Tickets</h1>
      <p className="ds-au-verdict">
        {view.configured ? `Issues are filed in ${view.provider === "jira" ? `Jira project ${view.target}` : `GitHub repository ${view.target}`}${view.enabled ? "." : " (paused)."}` : "This project files no tickets yet."}
      </p>
      {!view.credentials.jira && !view.credentials.github && (
        <p className="ds-au-meta">No Jira or GitHub credentials are stored for this organization yet (PUT /settings/integrations).</p>
      )}
      <div className="ds-ed-row">
        <label htmlFor={`${fid}-provider`}>Where</label>
        <select id={`${fid}-provider`} value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value as "jira" | "github" })}>
          <option value="jira" disabled={!view.credentials.jira}>Jira{view.credentials.jira ? "" : " (no credentials)"}</option>
          <option value="github" disabled={!view.credentials.github}>GitHub Issues{view.credentials.github ? "" : " (no token)"}</option>
        </select>
      </div>
      <div className="ds-ed-row">
        <label htmlFor={`${fid}-target`}>{jira ? "Jira project key" : "Repository (owner/name)"}</label>
        <input id={`${fid}-target`} value={form.target} placeholder={jira ? "PAY" : "acme/payments-api"} aria-invalid={message?.field === "target"}
               onChange={(e) => setForm({ ...form, target: e.target.value })} />
      </div>
      {jira && (
        <div className="ds-ed-row">
          <label htmlFor={`${fid}-type`}>Issue type</label>
          <input id={`${fid}-type`} value={form.issue_type ?? ""} placeholder="Bug" onChange={(e) => setForm({ ...form, issue_type: e.target.value || null })} />
        </div>
      )}
      <fieldset className="ds-ed-block">
        <legend>Who owns the status</legend>
        <label className="ds-ed-check">
          <input type="radio" name={`${fid}-src`} checked={form.status_source === "ticket"} onChange={() => setForm({ ...form, status_source: "ticket" })} />
          The ticket. Bulwark comments when it no longer detects the issue, and never closes it.
        </label>
        <label className="ds-ed-check">
          <input type="radio" name={`${fid}-src`} checked={form.status_source === "platform"} onChange={() => setForm({ ...form, status_source: "platform" })} />
          Bulwark. It closes the ticket when every issue on it is fixed and reopens it when one comes back.
        </label>
      </fieldset>
      {form.status_source === "ticket" && (
        <fieldset className="ds-ed-block">
          <legend>When the ticket moves to…</legend>
          <p className="ds-au-meta">
            Without a match: {Object.entries(view.effective_map).filter(([k]) => !rows.some((r) => r.status.toLowerCase() === k)).map(([k, v]) => `“${k}” → ${EFFECT_WORD[v] ?? v}`).join("; ") || "nothing"}.
            Bulwark never marks an issue fixed because a ticket closed: a scan or a tester decides.
          </p>
          <ul className="ds-ed-conds">
            {rows.map((r, i) => (
              <li key={i} className="ds-ed-cond">
                <input aria-label={`Status ${i + 1}`} value={r.status} placeholder={jira ? "In Review" : "closed"}
                       onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, status: e.target.value } : x)))} />
                <select aria-label={`Status ${i + 1}: what Bulwark does`} value={r.effect}
                        onChange={(e) => setRows(rows.map((x, j) => (j === i ? { ...x, effect: e.target.value } : x)))}>
                  {Object.entries(EFFECT_WORD).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
                <Button type="button" aria-label={`Remove status ${i + 1}`} onClick={() => setRows(rows.filter((_, j) => j !== i))}>×</Button>
              </li>
            ))}
          </ul>
          <Button type="button" onClick={() => setRows([...rows, { status: "", effect: "ready_for_retest" }])}>Add a status</Button>
        </fieldset>
      )}
      <label className="ds-ed-check"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> File and sync tickets for this project</label>
      {message && <p role={message.ok ? "status" : "alert"} className={message.ok ? "ds-au-meta" : "ds-au-error"}>{message.text}</p>}
      <div className="ds-au-actions"><Button type="submit" variant="primary">Save</Button></div>
    </form>
  );
}
