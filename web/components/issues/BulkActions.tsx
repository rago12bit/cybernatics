"use client";

import { useEffect, useId, useState } from "react";
import { ApiError, applyBulk, previewBulk, undoBulk } from "@/lib/api";
import type { BulkAction, BulkParams, BulkPreview, BulkResult, Selection } from "@/lib/issues";
import { Button } from "@/design-system/primitives/Button";
import { Dialog } from "@/design-system/primitives/Dialog";
import { RiskAcceptanceRequest } from "@/components/RiskAcceptanceRequest";

/* Bulk changes (plan §56; principle 9, "show the effect before the action"). Choosing an action
 * opens its dialog; the preview says, as counts, what will change, what already is as asked and
 * what is left alone and why. Only then can it be applied, naming the count the preview showed.
 * Afterwards, Undo for 10 seconds. Risk acceptance is a request per project, in its own flow. */

export const ACTION_TITLE: Record<BulkAction, string> = {
  assign: "Assign",
  not_a_risk: "Mark not a risk",
  reopen: "Reopen",
  tag: "Add a tag",
  untag: "Remove a tag",
  accept: "Request risk acceptance",
};

function message(e: unknown, fallback: string): string {
  if (e instanceof ApiError) return (e.data as { message?: string } | undefined)?.message ?? e.message;
  return fallback;
}

export function BulkDialog({ action, selection, selectedText, onClose, onDone }: {
  action: BulkAction | null;
  selection: Selection;
  selectedText: string;
  onClose: () => void;
  onDone: (r: BulkResult) => void;
}) {
  const id = useId();
  const [params, setParams] = useState<BulkParams>({});
  const [preview, setPreview] = useState<BulkPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [requesting, setRequesting] = useState<string | null>(null);
  const [requested, setRequested] = useState<Set<string>>(new Set());

  useEffect(() => {
    setParams({}); setPreview(null); setError(null); setRequesting(null); setRequested(new Set());
  }, [action]);

  // Reopen and risk acceptance need nothing more: preview straight away.
  useEffect(() => {
    if (action === "reopen" || action === "accept") void look({});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [action]);

  if (!action) return null;
  const needs = action === "assign" ? "to" : action === "not_a_risk" ? "reason" : action === "tag" || action === "untag" ? "tag" : null;
  const ready = needs === null || needs === "to" || Boolean(String(params[needs as keyof BulkParams] ?? "").trim());

  async function look(p: BulkParams) {
    if (!action) return;
    setBusy(true); setError(null);
    try { setPreview(await previewBulk({ ...selection, action, params: p })); }
    catch (e) { setPreview(null); setError(message(e, "Could not preview this change.")); }
    finally { setBusy(false); }
  }

  async function apply() {
    if (!action || !preview) return;
    setBusy(true); setError(null);
    try {
      onDone(await applyBulk({ ...selection, action, params, expected_count: preview.expected_count }));
    } catch (e) {
      // The list changed since the preview: show the new preview rather than guess.
      setError(message(e, "Could not make this change."));
      if (e instanceof ApiError && e.status === 409) void look(params);
    } finally { setBusy(false); }
  }

  const set = (patch: BulkParams) => { setParams((cur) => ({ ...cur, ...patch })); setPreview(null); };
  const projects = preview?.flow?.projects ?? [];
  const current = projects.find((p) => p.project_id === requesting);
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()} title={`${ACTION_TITLE[action]}: ${selectedText}`}
      description={action === "accept" ? "A request per project; someone other than you approves each. Until then the Issues stay open." : "Nothing changes until you confirm, and you can undo it for 10 seconds."}>
      <div className="iss-bulk">
        {needs === "to" && (
          <div className="iss-field">
            <label htmlFor={`${id}-to`} className="iss-label">Assign to</label>
            <input id={`${id}-to`} value={params.to ?? ""} placeholder="@handle; empty to unassign" onChange={(e) => set({ to: e.target.value })} />
          </div>
        )}
        {needs === "reason" && (
          <div className="iss-field">
            <label htmlFor={`${id}-reason`} className="iss-label">Why these are not a risk</label>
            <textarea id={`${id}-reason`} rows={3} maxLength={2000} value={params.reason ?? ""} onChange={(e) => set({ reason: e.target.value })} />
            <p className="iss-small iss-muted">Each Issue keeps this reason, and it is in the audit log.</p>
          </div>
        )}
        {needs === "tag" && (
          <div className="iss-field">
            <label htmlFor={`${id}-tag`} className="iss-label">Tag</label>
            <input id={`${id}-tag`} value={params.tag ?? ""} placeholder="pci" onChange={(e) => set({ tag: e.target.value })} />
          </div>
        )}
        {needs && !preview && (
          <Button type="button" onClick={() => look(params)} disabled={!ready || busy}>Preview the change</Button>
        )}
        {busy && !preview && <p role="status" className="iss-muted">Counting…</p>}
        {error && <p role="alert" className="iss-error">{error}</p>}
        {preview && (
          <div className="iss-preview" role="status">
            <p className="iss-sentence">{preview.sentence}</p>
            {preview.by_project.length > 0 && action !== "accept" && (
              <table className="iss-mini">
                <caption className="sr-only">Issues that will change, by project</caption>
                <thead><tr><th scope="col">Project</th><th scope="col" className="num">Will change</th></tr></thead>
                <tbody>{preview.by_project.map((p) => <tr key={p.project}><td>{p.project}</td><td className="num">{p.count.toLocaleString("en-US")}</td></tr>)}</tbody>
              </table>
            )}
            {action === "accept" ? (
              <>
                <ul className="iss-flow">
                  {projects.map((p) => (
                    <li key={p.project_id}>
                      <span>{p.project}: {p.count.toLocaleString("en-US")} Issue{p.count === 1 ? "" : "s"}{p.truncated ? ` (the first ${p.issue_ids.length} in this request)` : ""}</span>
                      {requested.has(p.project_id) ? <span className="iss-ok">Requested</span> : (
                        <Button type="button" onClick={() => setRequesting(p.project_id)} aria-label={`Request risk acceptance for ${p.project}`}>Request</Button>
                      )}
                    </li>
                  ))}
                </ul>
                {current && (
                  <div className="iss-subflow">
                    <h3>{current.project}</h3>
                    <RiskAcceptanceRequest assetId={current.project_id} issueIds={current.issue_ids}
                      onCancel={() => setRequesting(null)}
                      onDone={() => { setRequested((s) => new Set(s).add(current.project_id)); setRequesting(null); }} />
                  </div>
                )}
              </>
            ) : (
              <div className="iss-actions">
                <Button type="button" variant="primary" onClick={apply} disabled={busy || preview.will_change === 0}>
                  {preview.will_change === 0 ? "Nothing to change" : `Change ${preview.will_change.toLocaleString("en-US")} Issue${preview.will_change === 1 ? "" : "s"}`}
                </Button>
                <Button type="button" onClick={onClose}>Cancel</Button>
              </div>
            )}
          </div>
        )}
      </div>
    </Dialog>
  );
}

/** After a bulk change: what happened, and Undo while the server still allows it (10 seconds). */
export function UndoBar({ result, onUndone, onDismiss }: { result: BulkResult; onUndone: (sentence: string) => void; onDismiss: () => void }) {
  const until = result.undo_until ? Date.parse(result.undo_until) : 0;
  const [left, setLeft] = useState(() => Math.max(0, Math.ceil((until - Date.now()) / 1000)));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => setLeft(Math.max(0, Math.ceil((until - Date.now()) / 1000))), 250);
    return () => clearTimeout(t);
  }, [left, until]);
  async function undo() {
    setBusy(true); setError(null);
    try { onUndone((await undoBulk(result.batch_id)).sentence); }
    catch (e) { setError(message(e, "Could not undo.")); }
    finally { setBusy(false); }
  }
  return (
    <div className="iss-undo">
      <span role="status">{result.sentence}</span>
      {left > 0 && result.changed > 0 && (
        <Button type="button" onClick={undo} disabled={busy}>Undo <span className="iss-muted">({left}s)</span></Button>
      )}
      <button type="button" className="iss-x" onClick={onDismiss} aria-label="Dismiss">×</button>
      {error && <span role="alert" className="iss-error">{error}</span>}
    </div>
  );
}
