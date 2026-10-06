"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ApiError, getInbox, markNotificationsRead } from "@/lib/api";
import type { Inbox, NotificationItem } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import "./automation.css";

/** Plan §49: what Bulwark told you -- mentions, assignments, notes and retests on issues you watch,
 * SLA crossings, risk acceptances, tickets, rules waiting for you. Newest first; plain text. */

export const KIND_WORD: Record<string, string> = {
  mention: "Mention", assigned: "Assigned", note: "Note", retest: "Retest", sla: "SLA",
  risk_acceptance: "Risk acceptance", ticket: "Ticket", rules: "Rule",
};

const when = (iso: string) => new Date(iso).toLocaleString();

export function inboxVerdict(inbox: Inbox): string {
  if (!inbox.person) return "You are signed in with the shared token, which is nobody: notifications go to personal tokens.";
  if (inbox.unread) return `${inbox.unread} unread.`;
  return inbox.notifications.length ? "You are up to date." : "Nothing yet.";
}

export function InboxScreen() {
  const [inbox, setInbox] = useState<Inbox | null>(null);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getInbox(unreadOnly).then(
      (i) => setInbox(Array.isArray(i?.notifications) ? i : null),
      (e) => setError(e instanceof ApiError ? e.message : "Could not load your notifications."),
    );
  }, [unreadOnly]);
  useEffect(load, [load]);

  async function read(ids?: string[]) {
    try {
      await markNotificationsRead(ids);
      load();
      window.dispatchEvent(new Event("bulwark:inbox"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not mark them read.");
    }
  }

  if (error) return <p role="alert" className="ds-au-error">{error}</p>;
  if (!inbox) return <p role="status">Loading your notifications…</p>;
  return (
    <div className="ds-au">
      <div className="ds-au-top">
        <h1>Inbox</h1>
        <Link href="/app/settings/notifications">Notification settings</Link>
      </div>
      <p className="ds-au-verdict">{inboxVerdict(inbox)}</p>
      <div className="ds-au-actions">
        <Button aria-pressed={unreadOnly} onClick={() => setUnreadOnly(!unreadOnly)}>{unreadOnly ? "Show all" : "Unread only"}</Button>
        <Button disabled={!inbox.unread} onClick={() => read()}>Mark all read</Button>
      </div>
      {inbox.notifications.length > 0 && (
        <ol className="ds-au-list">
          {inbox.notifications.map((n: NotificationItem) => (
            <li key={n.id} className={`ds-in-item${n.read ? "" : " ds-in-unread"}`}>
              <p className="ds-in-head">
                <span className="ds-au-state">{KIND_WORD[n.kind] ?? n.kind}</span>{" "}
                {n.link ? (
                  <Link href={n.link} onClick={() => { if (!n.read) void read([n.id]); }}>{n.title}</Link>
                ) : (
                  <span>{n.title}</span>
                )}
                {!n.read && <span className="ds-in-dot"> · unread</span>}
              </p>
              {n.body && <p className="ds-in-body">{n.body.length > 300 ? `${n.body.slice(0, 300)}…` : n.body}</p>}
              <p className="ds-au-meta">
                <time dateTime={n.created_at}>{when(n.created_at)}</time>
                {n.email === "pending" && " · in your next daily digest"}
                {n.email === "sent" && " · emailed"}
                {!n.read && (
                  <>
                    {" · "}
                    <button type="button" className="ds-in-link" onClick={() => read([n.id])}>Mark read</button>
                  </>
                )}
              </p>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
