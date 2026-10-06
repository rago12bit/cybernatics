"use client";

import Link from "next/link";
import { useCallback, useEffect, useId, useState } from "react";
import {
  ApiError, fileIssueTicket, getIssueTicket, getWatchers, listIssueGroups, setIssueGroup, syncIssueTicket, unwatchIssue, watchIssue,
} from "@/lib/api";
import type { IssueGroupSummary, IssueTicket, Watchers } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./collab.css";

/** Plan §49 on the issue page: watching it, its group, and its ticket in Jira or GitHub Issues --
 * whose status comes from the ticket (or from Bulwark, if the project says so), and whose summary
 * and severity label come from Bulwark. */

const ago = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "never");
const PROVIDER = { jira: "Jira", github: "GitHub Issues" } as const;

export function WatchButton({ issueId }: { issueId: string }) {
  const [w, setW] = useState<Watchers | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    getWatchers(issueId).then((v) => setW(Array.isArray(v?.watchers) ? v : null), () => setW(null));
  }, [issueId]);
  if (!w) return null;
  async function toggle() {
    setError(null);
    try {
      setW(await (w!.watching ? unwatchIssue(issueId) : watchIssue(issueId)));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That did not work.");
    }
  }
  return (
    <div className="ds-watch">
      <Button onClick={toggle} aria-pressed={w.watching}>{w.watching ? "Watching" : "Watch"}</Button>
      <span className="ds-rt-meta">
        {w.watchers.length === 0 ? "Nobody watches this yet." : `Watching: ${w.watchers.map((x) => w.names[x.actor] ?? x.actor).join(", ")}`}
      </span>
      {error && <p role="alert" className="ds-rt-error">{error}</p>}
    </div>
  );
}

export function TicketPanel({ issueId, assetId, onChange }: { issueId: string; assetId: string; onChange?: () => void }) {
  const fid = useId();
  const [t, setT] = useState<IssueTicket | null>(null);
  const [groups, setGroups] = useState<IssueGroupSummary[]>([]);
  const [newGroup, setNewGroup] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getIssueTicket(issueId).then((v) => setT(v && "configured" in v ? v : null), () => setT(null));
    listIssueGroups(assetId).then((g) => setGroups(Array.isArray(g) ? g : []), () => setGroups([]));
  }, [issueId, assetId]);
  useEffect(load, [load]);

  async function run(fn: () => Promise<IssueTicket>, fallback: string) {
    setBusy(true);
    setError(null);
    try {
      setT(await fn());
      onChange?.();
      listIssueGroups(assetId).then((g) => setGroups(Array.isArray(g) ? g : []), () => undefined);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : fallback);
    } finally {
      setBusy(false);
    }
  }

  if (!t) return null;
  const tk = t.ticket;
  return (
    <section className="ds-tk" aria-labelledby={`${fid}-h`}>
      <div className="ds-issue-label" id={`${fid}-h`}>Ticket</div>
      {tk ? (
        <>
          <p className="ds-tk-line">
            <a href={tk.url} target="_blank" rel="noreferrer noopener">{tk.id}</a>
            {" "}in {PROVIDER[tk.provider]}: <strong>{tk.status ?? "not read yet"}</strong>
            {tk.assignee && <> · {tk.assignee}</>}
          </p>
          <p className="ds-rt-meta">
            Status comes from {t.status_source === "platform" ? "Bulwark (it closes and reopens the ticket)" : "the ticket"}; the summary and severity label from Bulwark. Synced {ago(tk.synced_at)}.
          </p>
          <div className="ds-rt-actions">
            <Button disabled={busy} onClick={() => run(() => syncIssueTicket(issueId), "Could not sync the ticket.")}>Sync now</Button>
            <Button disabled={busy} onClick={() => run(() => fileIssueTicket(issueId), "Could not update the ticket.")}>Update the ticket</Button>
          </div>
        </>
      ) : t.configured ? (
        <div className="ds-rt-actions">
          <Button disabled={busy} onClick={() => run(() => fileIssueTicket(issueId), "Could not file the ticket.")}>
            File {t.group ? "the group's" : "a"} ticket in {t.provider ? PROVIDER[t.provider] : "the tracker"}
          </Button>
        </div>
      ) : (
        <p className="ds-rt-meta">
          This project files no tickets yet. <Link href={`/app/projects/${assetId}/tickets`}>Ticket settings</Link>
        </p>
      )}

      <label htmlFor={`${fid}-group`} className="ds-rt-label">Group</label>
      <select id={`${fid}-group`} className="ds-owner-select" value={t.group?.id ?? ""} disabled={busy}
              onChange={(e) => run(() => setIssueGroup(issueId, { group_id: e.target.value || null }), "Could not change the group.")}>
        <option value="">Not in a group</option>
        {groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({g.count})</option>)}
      </select>
      <form className="ds-tag-add" onSubmit={(e) => {
        e.preventDefault();
        if (newGroup.trim()) void run(() => setIssueGroup(issueId, { name: newGroup.trim() }), "Could not make the group.").then(() => setNewGroup(""));
      }}>
        <input aria-label="New group name" placeholder="New group" maxLength={120} value={newGroup} onChange={(e) => setNewGroup(e.target.value)} />
        <Button type="submit" disabled={!newGroup.trim() || busy}>Add</Button>
      </form>
      {t.group && <p className="ds-rt-meta">One ticket tracks the group&apos;s {t.group.count} issue{t.group.count === 1 ? "" : "s"}.</p>}
      {error && <p role="alert" className="ds-rt-error">{error}</p>}
    </section>
  );
}
