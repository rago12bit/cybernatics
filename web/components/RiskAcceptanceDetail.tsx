"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import {
  ApiError, actOnRiskAcceptance, evidenceDownloadUrl, extendRiskAcceptance, getRiskAcceptance,
  getRiskAcceptancePolicy, type RiskAcceptanceAction,
} from "@/lib/api";
import type { RiskAcceptance, RiskAcceptancePolicy } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { STATE_WORD } from "./RiskAcceptancesScreen";
import { Loading } from "@/design-system/primitives/Loading";
import "./risk-acceptance.css";
import { formatDate, formatDateTime, projectName } from "@/lib/format";

/** One risk acceptance (plan §44.2, §55.3): what was asked and why, its issues and proof, every
 * step from the audit log, and what you may do next. The server decides who may approve; the
 * buttons only appear when it says you can. */

const when = (iso: string) => formatDateTime(iso);
const day = (iso: string) => formatDate(iso);

export function RiskAcceptanceDetail({ id }: { id: string }) {
  const fid = useId();
  const [ra, setRa] = useState<RiskAcceptance | null>(null);
  const [policy, setPolicy] = useState<RiskAcceptancePolicy | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [extendTo, setExtendTo] = useState("");
  const [extendWhy, setExtendWhy] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  const load = useCallback(() => {
    getRiskAcceptance(id).then(setRa, (e) => setError(e instanceof ApiError ? e.message : "Could not load."));
    getRiskAcceptancePolicy().then(setPolicy, () => setPolicy(null));
  }, [id]);
  useEffect(load, [load]);

  async function run(action: RiskAcceptanceAction, message: string, withNote = false) {
    setBusy(true);
    setError(null);
    try {
      setRa(await actOnRiskAcceptance(id, action, withNote ? note : undefined));
      setNote("");
      setDone(message);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That did not work.");
    } finally {
      setBusy(false);
    }
  }

  async function extend(e: React.FormEvent) {
    e.preventDefault();
    if (!extendTo) return setError("Choose the new expiry.");
    setBusy(true);
    setError(null);
    try {
      const next = await extendRiskAcceptance(id, new Date(`${extendTo}T23:59:00`).toISOString(), extendWhy || undefined);
      window.location.assign(`/app/risk-acceptances/${next.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not request the extension.");
    } finally {
      setBusy(false);
    }
  }

  async function download(fileId: string) {
    try {
      window.location.assign(await evidenceDownloadUrl(fileId));
    } catch {
      setError("Could not get a download link.");
    }
  }

  if (!ra) return error ? <p role="alert">{error}</p> : <Loading />;
  const mine = policy?.you === ra.requested_by;
  const who = (actor: string | null) => (actor ? (ra.names?.[actor] ?? actor) : "—");

  return (
    <div className="ds-ra-page ds-ra-detail">
      <p><Link href="/app/risk-acceptances">← Risk acceptance</Link></p>
      <h1>{ra.decision.charAt(0).toUpperCase() + ra.decision.slice(1)}: {ra.issue_count} issue{ra.issue_count === 1 ? "" : "s"} in {projectName(ra.project)}</h1>
      <p className={`ds-ra-verdict ds-ra-state-${ra.state}`}>
        {STATE_WORD[ra.state]}
        {ra.state === "requested" && ` -- ${ra.approver ? `asked ${who(ra.approver)}` : "anyone but the requester can decide"}. The issues stay open until then.`}
        {ra.state === "approved" && ` until ${day(ra.expires_at)}.`}
        {ra.state === "expired" && (ra.ended_reason === "expire_now" ? ` early, by ${who(ra.ended_by)}; the issues are open again.` : `; the issues are open again.`)}
      </p>
      {ra.legacy && <p className="ds-ra-meta">This was accepted by one person through triage, before approvals existed; nobody else approved it.</p>}
      {error && <p role="alert" className="ds-ra-field-error">{error}</p>}
      {done && <p role="status">{done}</p>}

      {ra.state === "requested" && ra.can_decide && (
        <section className="ds-ra-decide" aria-labelledby={`${fid}-decide`}>
          <h2 id={`${fid}-decide`}>Your decision</h2>
          <label htmlFor={`${fid}-note`}>Note (required to reject)</label>
          <textarea id={`${fid}-note`} rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
          <div className="ds-ra-actions">
            <Button onClick={() => run("reject", "Rejected.", true)} disabled={busy || !note.trim()}>Reject</Button>
            <Button variant="primary" onClick={() => run("approve", "Approved. The issues are accepted until the expiry.", true)} disabled={busy}>Approve</Button>
          </div>
        </section>
      )}
      {ra.state === "requested" && !ra.can_decide && (
        <p className="ds-ra-meta">
          {mine ? "You asked for this, so someone else has to decide." : policy && !policy.can_approve ? "Deciding needs a personal API token: the shared token could be anyone." : "You cannot decide this one."}
        </p>
      )}

      <dl>
        <dt>Why</dt><dd>{ra.justification}</dd>
        <dt>Controls</dt><dd>{ra.controls || "—"}</dd>
        <dt>Requested</dt><dd>by {who(ra.requested_by)}, {when(ra.requested_at)}</dd>
        <dt>Expires</dt><dd>{day(ra.expires_at)} ({ra.days} days){ra.restart_sla ? "; the issues' SLA clock restarts then" : ""}</dd>
        {ra.decided_by && <><dt>{ra.state === "rejected" ? "Rejected" : "Approved"}</dt><dd>by {who(ra.decided_by)}{ra.decided_at ? `, ${when(ra.decided_at)}` : ""}{ra.decision_note ? `: ${ra.decision_note}` : ""}</dd></>}
        {ra.extends_id && <><dt>Extends</dt><dd><Link href={`/app/risk-acceptances/${ra.extends_id}`}>the earlier acceptance</Link></dd></>}
        <dt>Proof</dt>
        <dd>
          {ra.proof_links.length === 0 && ra.proof_files.length === 0 && "None."}
          <ul className="ds-ra-proof">
            {ra.proof_links.map((l) => <li key={l}><a href={l} rel="noopener noreferrer nofollow" target="_blank">{l}</a></li>)}
            {ra.proof_files.map((f) => (
              <li key={f.id}>
                <button type="button" className="ds-ra-link" onClick={() => download(f.id)}>{f.file_name}</button> ({f.content_type}, {Math.ceil(f.size_bytes / 1024)} KB){f.active_content && " -- can contain script; it only downloads"}
              </li>
            ))}
          </ul>
        </dd>
      </dl>

      <h2>Issues</h2>
      <ul className="ds-ra-proof">
        {ra.issues.map((i) => (
          <li key={i.id}>
            <Link href={`/app/projects/${ra.project_id}/issues/${i.id}`}>{i.title}</Link> <span className="ds-ra-meta">{i.severity.toLowerCase()} · {i.path} · {i.triage_status === "accepted" ? "accepted" : "open"}</span>
          </li>
        ))}
      </ul>

      <div className="ds-ra-actions" style={{ justifyContent: "flex-start", margin: "1rem 0" }}>
        {ra.state === "requested" && mine && <Button onClick={() => run("withdraw", "Withdrawn.")} disabled={busy}>Withdraw request</Button>}
        {ra.state === "approved" && <Button onClick={() => run("expire", "Expired now. The issues are open again.")} disabled={busy}>Expire now</Button>}
        {ra.state === "expired" && ra.ended_reason === "expire_now" && new Date(ra.expires_at) > new Date() && (
          <Button onClick={() => run("reinstate", "Reinstated, until the approved date.")} disabled={busy}>Reinstate</Button>
        )}
      </div>

      {ra.state === "approved" && (
        <form onSubmit={extend} className="ds-ra-decide" aria-labelledby={`${fid}-ext`}>
          <h2 id={`${fid}-ext`}>Extend</h2>
          <p className="ds-ra-meta">An extension is a new request; someone other than you approves it. This one stays in force meanwhile.</p>
          <label htmlFor={`${fid}-to`}>New expiry</label>
          <input id={`${fid}-to`} type="date" value={extendTo} onChange={(e) => setExtendTo(e.target.value)} min={ra.expires_at.slice(0, 10)} />
          <label htmlFor={`${fid}-why`}>Why it needs longer</label>
          <textarea id={`${fid}-why`} rows={2} value={extendWhy} onChange={(e) => setExtendWhy(e.target.value)} />
          <div className="ds-ra-actions"><Button type="submit" disabled={busy}>Request extension</Button></div>
        </form>
      )}

      <h2>Every step</h2>
      <ol className="ds-ra-proof">
        {ra.trail.map((t, i) => <li key={i}>{when(t.at)}: {t.action.replace(/_/g, " ")} by {who(t.actor)}</li>)}
      </ol>
    </div>
  );
}
