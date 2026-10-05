"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, listMentions } from "@/lib/api";
import type { Mention } from "@/lib/types";
import "./collab.css";

/** Plan §49: notes that @mention you, newest first. "You" is the API token you signed in with,
 * until user accounts exist (Week 75). */
export function MentionsScreen() {
  const [items, setItems] = useState<Mention[] | null>(null);
  const [names, setNames] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listMentions().then(
      (r) => { setItems(Array.isArray(r?.mentions) ? r.mentions : []); setNames(r?.names ?? {}); },
      (e) => setError(e instanceof ApiError ? e.message : "Could not load mentions."),
    );
  }, []);

  if (error) return <p role="alert" className="ds-rt-error">{error}</p>;
  if (!items) return <p role="status">Loading mentions…</p>;
  return (
    <div className="ds-mentions">
      <h1>Mentions</h1>
      <p className="ds-rt-meta">Notes that mention you. You are the API token you signed in with; the shared token is never mentioned.</p>
      {items.length === 0 ? (
        <p>Nobody has mentioned you yet.</p>
      ) : (
        <ol className="ds-note-list">
          {items.map((m) => (
            <li key={m.note.id} className="ds-note">
              <p className="ds-note-head">
                <strong>{names[m.note.author] ?? m.note.author}</strong> on{" "}
                <Link href={`/app/projects/${m.project_id}/issues/${m.note.issue_id}`}>{m.issue_title}</Link>{" "}
                <time dateTime={m.note.created_at} className="ds-rt-meta">{new Date(m.note.created_at).toLocaleString()}</time>
              </p>
              <p className="ds-note-body">{m.note.body.length > 400 ? `${m.note.body.slice(0, 400)}…` : m.note.body}</p>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
