"use client";

import { useEffect, useId, useMemo, useState } from "react";
import { ApiError, addRiskAcceptanceProof, getRiskAcceptancePolicy, requestRiskAcceptance } from "@/lib/api";
import type { RiskAcceptance, RiskAcceptancePolicy, RiskDecision } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./risk-acceptance.css";

/** Plan §55.3: request risk acceptance for one or more issues. The approver list leaves out the
 * requester, and the server enforces the same rule (plan §44.2), so this form is a convenience,
 * not the control. The issues stay open until someone else approves. */

const DECISIONS: [RiskDecision, string][] = [["accept", "Accept"], ["mitigate", "Mitigate"], ["transfer", "Transfer"], ["avoid", "Avoid"]];
const DAY = 86_400_000;

type FieldError = { field: string; message: string };

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** End of the chosen day, local time -- "30 November" means until that day is over. */
function endOfDay(day: string): Date {
  return new Date(`${day}T23:59:00`);
}

export function RiskAcceptanceRequest({
  assetId,
  issueIds,
  onDone,
  onCancel,
}: {
  assetId: string;
  issueIds: string[];
  onDone: (ra: RiskAcceptance) => void;
  onCancel: () => void;
}) {
  const id = useId();
  const [policy, setPolicy] = useState<RiskAcceptancePolicy | null>(null);
  const [decision, setDecision] = useState<RiskDecision>("accept");
  const [why, setWhy] = useState("");
  const [controls, setControls] = useState("");
  const [links, setLinks] = useState<string[]>([]);
  const [link, setLink] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [expires, setExpires] = useState("");
  const [approver, setApprover] = useState("");
  const [restartSla, setRestartSla] = useState(true);
  const [fieldError, setFieldError] = useState<FieldError | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getRiskAcceptancePolicy().then(setPolicy, () => setPolicy({ max_days: 90, you: "", approvers: [], can_approve: false }));
  }, []);

  const maxDay = useMemo(() => isoDay(new Date(Date.now() + (policy?.max_days ?? 90) * DAY)), [policy]);
  const days = expires ? Math.max(0, Math.round((endOfDay(expires).getTime() - Date.now()) / DAY)) : null;
  const who = policy?.approvers.find((a) => a.actor === approver)?.name;
  const n = issueIds.length;

  function addLink() {
    const v = link.trim();
    if (v && !links.includes(v)) setLinks((l) => [...l, v]);
    setLink("");
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setFieldError(null);
    setError(null);
    if (!expires) return setFieldError({ field: "expires_at", message: "Choose when it expires." });
    setSaving(true);
    try {
      const ra = await requestRiskAcceptance(assetId, {
        issue_ids: issueIds, decision, justification: why, controls,
        proof_links: link.trim() ? [...links, link.trim()] : links,
        expires_at: endOfDay(expires).toISOString(), restart_sla: restartSla,
        approver: approver || undefined,
      });
      for (const f of files) await addRiskAcceptanceProof(ra.id, f);
      onDone(ra);
    } catch (err) {
      const d = err instanceof ApiError ? (err.data as Partial<FieldError> | undefined) : undefined;
      if (d?.field && d.message) setFieldError({ field: d.field, message: d.message });
      else setError(err instanceof ApiError ? err.message : "Could not send the request.");
    } finally {
      setSaving(false);
    }
  }

  const fid = (f: string) => `${id}-${f}`;
  const errFor = (f: string) =>
    fieldError?.field === f ? <p id={`${fid(f)}-err`} className="ds-ra-field-error">{fieldError.message}</p> : null;
  const aria = (f: string) => ({
    "aria-invalid": fieldError?.field === f || undefined,
    "aria-describedby": fieldError?.field === f ? `${fid(f)}-err` : undefined,
  });

  return (
    <form className="ds-ra-form" onSubmit={submit} noValidate aria-label={`Request risk acceptance for ${n} issue${n === 1 ? "" : "s"}`}>
      {error && <p role="alert" className="ds-ra-field-error">{error}</p>}
      {fieldError && <p role="alert" className="ds-ra-sr">{fieldError.message}</p>}
      <fieldset className="ds-ra-row">
        <legend>Decision</legend>
        <div className="ds-ra-options">
          {DECISIONS.map(([v, label]) => (
            <label key={v} className="ds-ra-choice">
              <input type="radio" name={fid("decision")} value={v} checked={decision === v} onChange={() => setDecision(v)} /> {label}
            </label>
          ))}
        </div>
        {errFor("decision")}
      </fieldset>
      <div className="ds-ra-row">
        <label htmlFor={fid("justification")}>Why</label>
        <textarea id={fid("justification")} rows={3} value={why} onChange={(e) => setWhy(e.target.value)} {...aria("justification")}
          placeholder="Legacy export service, retired on 30 November. Only reachable over the VPN." />
        {errFor("justification")}
      </div>
      <div className="ds-ra-row">
        <label htmlFor={fid("controls")}>Controls</label>
        <textarea id={fid("controls")} rows={2} value={controls} onChange={(e) => setControls(e.target.value)} {...aria("controls")}
          placeholder="What limits the risk meanwhile, e.g. WAF rule 9412 blocks the payload pattern" />
        {errFor("controls")}
      </div>
      <div className="ds-ra-row">
        <label htmlFor={fid("link")}>Proof (links and files)</label>
        <div className="ds-ra-inline">
          <input id={fid("link")} type="url" value={link} onChange={(e) => setLink(e.target.value)} placeholder="https://…" {...aria("proof_links")}
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addLink(); } }} />
          <Button type="button" onClick={addLink} disabled={!link.trim()}>Add link</Button>
          <input type="file" multiple onChange={(e) => setFiles(Array.from(e.target.files ?? []))} aria-label="Add proof files" />
        </div>
        {errFor("proof_links")}
        {(links.length > 0 || files.length > 0) && (
          <ul className="ds-ra-proof">
            {links.map((l) => (
              <li key={l}>{l} <button type="button" className="ds-ra-link" onClick={() => setLinks((x) => x.filter((y) => y !== l))} aria-label={`Remove ${l}`}>remove</button></li>
            ))}
            {files.map((f) => <li key={f.name}>{f.name} ({Math.ceil(f.size / 1024)} KB)</li>)}
          </ul>
        )}
      </div>
      <div className="ds-ra-row">
        <label htmlFor={fid("expires_at")}>Expires</label>
        <div className="ds-ra-inline">
          <input id={fid("expires_at")} type="date" value={expires} min={isoDay(new Date(Date.now() + DAY))} max={maxDay}
            onChange={(e) => setExpires(e.target.value)} {...aria("expires_at")} />
          <span className="ds-ra-hint">{days !== null && `${days} day${days === 1 ? "" : "s"} · `}Policy maximum: {policy?.max_days ?? 90} days</span>
        </div>
        {errFor("expires_at")}
      </div>
      <div className="ds-ra-row">
        <label htmlFor={fid("approver")}>Approver</label>
        <select id={fid("approver")} value={approver} onChange={(e) => setApprover(e.target.value)} {...aria("approver")}>
          <option value="">Someone other than you</option>
          {(policy?.approvers ?? []).map((a) => <option key={a.actor} value={a.actor}>{a.name}</option>)}
        </select>
        {errFor("approver")}
      </div>
      <label className="ds-ra-choice ds-ra-check">
        <input type="checkbox" checked={restartSla} onChange={(e) => setRestartSla(e.target.checked)} /> On expiry, reopen the issues and restart their SLA clock
      </label>
      {errFor("issue_ids")}
      <p className="ds-ra-note">
        {who ? `${who} gets a notification.` : "Your team's channels get a notification."} The issue{n === 1 ? " stays" : "s stay"} open until someone else approves.
      </p>
      <div className="ds-ra-actions">
        <Button type="button" onClick={onCancel}>Cancel</Button>
        <Button variant="primary" type="submit" disabled={saving}>{saving ? "Sending…" : "Send request"}</Button>
      </div>
    </form>
  );
}
