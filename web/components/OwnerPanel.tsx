"use client";

import { useCallback, useEffect, useId, useState } from "react";
import { ApiError, getIssueOwner, listPeople, setIssueAssignee, setIssuePriority } from "@/lib/api";
import type { IssueOwner, Person } from "@/lib/types";
import "./collab.css";

/** Plan §45: who owns the fix, and a priority band set by hand. Either may have been set by a rule,
 * which the panel names. People are the organization's personal API tokens until accounts exist. */

const BANDS = ["P1", "P2", "P3", "P4"];

export function OwnerPanel({ issueId, onChange }: { issueId: string; onChange?: () => void }) {
  const fid = useId();
  const [owner, setOwner] = useState<IssueOwner | null>(null);
  const [people, setPeople] = useState<Person[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    getIssueOwner(issueId).then((o) => setOwner(o && "assignee" in o ? o : null), () => setOwner(null));
    listPeople().then((p) => setPeople(Array.isArray(p) ? p : []), () => setPeople([]));
  }, [issueId]);
  useEffect(load, [load]);

  async function run(fn: () => Promise<IssueOwner>, fallback: string) {
    setBusy(true);
    setError(null);
    try {
      setOwner(await fn());
      onChange?.();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : fallback);
    } finally {
      setBusy(false);
    }
  }

  if (!owner) return null;
  const by = (actor: string | null) => (actor ? owner.names[actor] ?? actor : null);
  const handles = new Set(people.map((p) => p.handle));

  return (
    <section className="ds-owner" aria-labelledby={`${fid}-h`}>
      <div className="ds-issue-label" id={`${fid}-h`}>Owner</div>
      <label htmlFor={`${fid}-who`} className="ds-rt-label">Assigned to</label>
      <select
        id={`${fid}-who`}
        className="ds-owner-select"
        value={owner.assignee_handle ?? ""}
        disabled={busy}
        onChange={(e) => run(() => setIssueAssignee(issueId, e.target.value || null), "Could not assign.")}
      >
        <option value="">Nobody</option>
        {owner.assignee_handle && !handles.has(owner.assignee_handle) && (
          <option value={owner.assignee_handle}>{owner.assignee_name ?? owner.assignee_handle}</option>
        )}
        {people.map((p) => (
          <option key={p.actor} value={p.handle}>{p.name} (@{p.handle})</option>
        ))}
      </select>

      <label htmlFor={`${fid}-band`} className="ds-rt-label">Priority</label>
      <select
        id={`${fid}-band`}
        className="ds-owner-select"
        value={owner.priority_override ?? ""}
        disabled={busy}
        onChange={(e) => run(() => setIssuePriority(issueId, e.target.value || null), "Could not set the priority.")}
      >
        <option value="">{owner.computed_band ? `As computed (${owner.computed_band})` : "As computed"}</option>
        {BANDS.map((b) => <option key={b} value={b}>{b}</option>)}
      </select>
      {owner.priority_override && (
        <p className="ds-rt-meta">
          Set by {by(owner.priority_override_by) ?? "someone"}
          {owner.computed_band && owner.computed_band !== owner.priority_override ? `; computed ${owner.computed_band}` : ""}.
        </p>
      )}
      {error && <p role="alert" className="ds-rt-error">{error}</p>}
    </section>
  );
}
