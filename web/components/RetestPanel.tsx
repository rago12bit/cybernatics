"use client";

import { useCallback, useEffect, useId, useState } from "react";
import { ApiError, getRetest, retestStep, runTargetedRetest } from "@/lib/api";
import type { Retest, RetestAction } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./collab.css";

/** Plan §43.3: a developer marks the issue ready for retest; a tester confirms it fixed or
 * reproduces it (with a note). When one rule or one DAST template can check it, a targeted retest
 * re-runs only that, against only that location. */

const POLL_MS = 2000;
const day = (iso: string) => new Date(iso).toLocaleDateString();

export function RetestPanel({ issueId, onChange }: { issueId: string; onChange?: () => void }) {
  const fid = useId();
  const [r, setR] = useState<Retest | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getRetest(issueId).then((v) => setR(Array.isArray(v?.runs) ? v : null), () => setR(null));
  }, [issueId]);
  useEffect(load, [load]);

  const running = !!r?.runs.some((x) => x.status === "queued" || x.status === "running");
  useEffect(() => {
    if (!running) return;
    const t = setTimeout(() => {
      getRetest(issueId).then((next) => {
        setR(next);
        if (!next.runs.some((x) => x.status === "queued" || x.status === "running")) onChange?.();
      }, () => undefined);
    }, POLL_MS);
    return () => clearTimeout(t);
  }, [running, r, issueId, onChange]);

  async function act(action: RetestAction) {
    setBusy(true);
    setError(null);
    try {
      setR(await retestStep(issueId, action, note.trim() || undefined));
      setNote("");
      onChange?.();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That did not work.");
    } finally {
      setBusy(false);
    }
  }

  async function runTargeted() {
    setBusy(true);
    setError(null);
    try {
      setR(await runTargetedRetest(issueId));
      onChange?.();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start the retest.");
    } finally {
      setBusy(false);
    }
  }

  if (!r) return null;
  const who = (a: string | null) => {
    if (!a) return "someone";
    if (a.startsWith("ticket:")) return `its ticket, ${a.slice(7)}`;
    if (a.startsWith("rule:")) return r.names[a] ?? "a rule";
    return r.names[a] ?? a;
  };
  const open = r.state !== "fixed";
  const latest = r.runs[0];

  return (
    <section className="ds-rt" aria-labelledby={`${fid}-h`}>
      <div className="ds-issue-label" id={`${fid}-h`}>Retest</div>
      <p className={`ds-rt-status ds-rt-${r.status ?? "none"}`}>
        {r.status === null && (open ? "No retest requested." : "Fixed.")}
        {r.status === "requested" && <>Ready for retest: asked by {who(r.requested_by)}{r.requested_at && ` on ${day(r.requested_at)}`}.</>}
        {r.status === "passed" && <>Retest passed{r.decided_by && `: ${who(r.decided_by)}`}{r.decided_at && `, ${day(r.decided_at)}`}.</>}
        {r.status === "failed" && <>Retest failed{r.decided_by && `: ${who(r.decided_by)}`}{r.decided_at && `, ${day(r.decided_at)}`}. Still open.</>}
      </p>
      {r.note && <p className="ds-rt-note">{r.note}</p>}
      {error && <p role="alert" className="ds-rt-error">{error}</p>}

      {open && (
        <>
          <label htmlFor={`${fid}-note`} className="ds-rt-label">
            {r.status === "requested" ? "Note (required if it reproduces)" : "Note (optional)"}
          </label>
          <textarea id={`${fid}-note`} rows={2} value={note} onChange={(e) => setNote(e.target.value)} className="ds-rt-input"
            placeholder={r.status === "requested" ? "What you tried, on which build" : "What changed, e.g. fixed in #412"} />
          <div className="ds-rt-actions">
            {r.status !== "requested" && <Button onClick={() => act("request")} disabled={busy}>Ready for retest</Button>}
            {r.status === "requested" && (
              <>
                <Button variant="primary" onClick={() => act("confirm_fixed")} disabled={busy}>Confirmed fixed</Button>
                <Button onClick={() => act("reproduced")} disabled={busy || !note.trim()}>Reproduced</Button>
                <Button onClick={() => act("cancel")} disabled={busy}>Cancel request</Button>
              </>
            )}
          </div>
        </>
      )}

      {open && r.targeted.available && (
        <div className="ds-rt-targeted">
          <p className="ds-rt-meta">
            Targeted retest: {r.targeted.kind === "dast" ? "template" : "rule"} <code>{r.targeted.rule}</code> ({r.targeted.tool}) against{" "}
            <code>{r.targeted.location}</code> only.
          </p>
          <Button onClick={runTargeted} disabled={busy || running}>{running ? "Retesting…" : "Run the targeted retest"}</Button>
        </div>
      )}
      {open && !r.targeted.available && r.targeted.reason && r.status === "requested" && (
        <p className="ds-rt-meta">{r.targeted.reason}</p>
      )}
      {latest && (
        <p className="ds-rt-meta" role="status">
          Last targeted retest:{" "}
          {latest.status === "queued" || latest.status === "running"
            ? "running…"
            : latest.status === "failed"
              ? `could not run (${latest.detail ?? "unknown error"})`
              : latest.detail}
        </p>
      )}
    </section>
  );
}
