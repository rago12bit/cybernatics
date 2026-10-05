"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ApiError, listRiskAcceptances } from "@/lib/api";
import type { RiskAcceptance } from "@/lib/types";
import "./risk-acceptance.css";

/** Plan §55.3: the approvals queue -- requests waiting for someone other than their requester --
 * then what is in force and what has ended. Whether *you* may decide is the server's answer
 * (`can_decide`), never worked out here. */

export const STATE_WORD: Record<RiskAcceptance["state"], string> = {
  requested: "Waiting for approval",
  approved: "Approved",
  rejected: "Rejected",
  withdrawn: "Withdrawn",
  expired: "Expired",
  extended: "Replaced by an extension",
};

const date = (iso: string) => new Date(iso).toLocaleDateString();

export function approvalsVerdict(all: RiskAcceptance[]): string {
  const mine = all.filter((r) => r.state === "requested" && r.can_decide).length;
  const waiting = all.filter((r) => r.state === "requested").length;
  if (mine) return `${mine} request${mine === 1 ? "" : "s"} waiting for your decision.`;
  if (waiting) return `${waiting} request${waiting === 1 ? "" : "s"} waiting for someone else's decision.`;
  return "Nothing is waiting for approval.";
}

export function AcceptanceItem({ r }: { r: RiskAcceptance }) {
  return (
    <li className="ds-ra-item">
      <div className="ds-ra-item-head">
        <Link href={`/app/risk-acceptances/${r.id}`}>
          {r.decision.charAt(0).toUpperCase() + r.decision.slice(1)}: {r.issue_count} issue{r.issue_count === 1 ? "" : "s"} in {r.project}
        </Link>
        <span className={`ds-ra-state ds-ra-state-${r.state}`}>{STATE_WORD[r.state]}</span>
        {r.legacy && <span className="ds-ra-meta">accepted alone, before approvals</span>}
      </div>
      <p className="ds-ra-meta">
        Requested by {r.names?.[r.requested_by] ?? r.requested_by} on {date(r.requested_at)} · until {date(r.expires_at)} ({r.days} days)
        {r.decided_by && ` · ${r.state === "rejected" ? "rejected" : "approved"} by ${r.names?.[r.decided_by] ?? r.decided_by}`}
      </p>
      <p>{r.justification.length > 200 ? `${r.justification.slice(0, 200)}…` : r.justification}</p>
    </li>
  );
}

export function RiskAcceptancesScreen() {
  const [rows, setRows] = useState<RiskAcceptance[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    listRiskAcceptances().then(setRows, (e) => setError(e instanceof ApiError ? e.message : "Could not load."));
  }, []);
  useEffect(load, [load]);

  if (error) return <p role="alert">{error}</p>;
  if (!rows) return <p role="status">Loading…</p>;
  const waiting = rows.filter((r) => r.state === "requested");
  const live = rows.filter((r) => r.state === "approved");
  const ended = rows.filter((r) => r.state !== "requested" && r.state !== "approved");

  return (
    <div className="ds-ra-page">
      <h1>Risk acceptance</h1>
      <p className="ds-ra-verdict">{approvalsVerdict(rows)}</p>
      <section aria-labelledby="ra-waiting">
        <h2 id="ra-waiting">Waiting for approval</h2>
        {waiting.length === 0 ? <p className="ds-ra-meta">None.</p> : <ul className="ds-ra-list">{waiting.map((r) => <AcceptanceItem key={r.id} r={r} />)}</ul>}
      </section>
      <section aria-labelledby="ra-live">
        <h2 id="ra-live">In force</h2>
        {live.length === 0 ? <p className="ds-ra-meta">None.</p> : <ul className="ds-ra-list">{live.map((r) => <AcceptanceItem key={r.id} r={r} />)}</ul>}
      </section>
      {ended.length > 0 && (
        <section aria-labelledby="ra-ended">
          <h2 id="ra-ended">Ended</h2>
          <ul className="ds-ra-list">{ended.map((r) => <AcceptanceItem key={r.id} r={r} />)}</ul>
        </section>
      )}
      <p className="ds-ra-meta">To request one, select issues in a project&apos;s issues table, or open an issue.</p>
    </div>
  );
}
