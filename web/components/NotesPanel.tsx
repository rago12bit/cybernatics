"use client";

import { Fragment, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { ApiError, addNote, attachToNote, deleteNote, editNote, listNotes, listPeople, noteFileLink } from "@/lib/api";
import type { Note, NotesView, Person } from "@/lib/types";
import { Button } from "@/design-system/primitives/Button";
import { ConfirmButton } from "@/design-system/primitives/ConfirmButton";
import "./collab.css";
import { formatDateTime } from "@/lib/format";

/** Plan §49: notes on an issue, threaded, with @mentions. Bodies are shown as plain text -- never
 * HTML or Markdown -- with known @handles marked. Files attached to a note are never shown inline:
 * they download through a short-lived link from the separate attachments origin. */

const MENTION = /(^|[^\w@.])@([a-z0-9][a-z0-9._-]{0,63})/gi;
const when = (iso: string) => formatDateTime(iso);

function Body({ text, handles }: { text: string; handles: Set<string> }) {
  const parts: React.ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(MENTION)) {
    const handle = m[2]!.toLowerCase().replace(/[._-]+$/, "");
    if (!handles.has(handle)) continue;
    const start = m.index! + m[1]!.length;
    parts.push(text.slice(last, start));
    parts.push(<span key={start} className="ds-note-mention">@{m[2]}</span>);
    last = start + 1 + m[2]!.length;
  }
  parts.push(text.slice(last));
  return <p className="ds-note-body">{parts}</p>;
}

function Composer({
  label,
  people,
  initial = "",
  submitLabel,
  withFiles,
  onSubmit,
  onCancel,
}: {
  label: string;
  people: Person[];
  initial?: string;
  submitLabel: string;
  withFiles?: boolean;
  onSubmit: (body: string, files: File[]) => Promise<void>;
  onCancel?: () => void;
}) {
  const id = useId();
  const ref = useRef<HTMLTextAreaElement>(null);
  const [text, setText] = useState(initial);
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState<string | null>(null);

  const matches = query === null ? [] : people.filter((p) => p.handle.startsWith(query) || p.name.toLowerCase().includes(query)).slice(0, 6);

  function onType(v: string, caret: number) {
    setText(v);
    const m = /(?:^|[^\w@.])@([a-z0-9._-]*)$/i.exec(v.slice(0, caret));
    setQuery(m ? m[1]!.toLowerCase() : null);
  }

  function pick(p: Person) {
    const el = ref.current;
    const caret = el?.selectionStart ?? text.length;
    const before = text.slice(0, caret).replace(/@([a-z0-9._-]*)$/i, `@${p.handle} `);
    setText(before + text.slice(caret));
    setQuery(null);
    requestAnimationFrame(() => {
      el?.focus();
      el?.setSelectionRange(before.length, before.length);
    });
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim()) return setError("Write something first.");
    setBusy(true);
    setError(null);
    try {
      await onSubmit(text, files);
      setText("");
      setFiles([]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save the note.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="ds-note-form" onSubmit={submit}>
      <label htmlFor={`${id}-t`} className="ds-rt-label">{label}</label>
      <textarea
        id={`${id}-t`}
        ref={ref}
        rows={3}
        value={text}
        className="ds-rt-input"
        aria-describedby={`${id}-hint`}
        aria-autocomplete="list"
        aria-controls={matches.length ? `${id}-people` : undefined}
        onChange={(e) => onType(e.target.value, e.target.selectionStart)}
        onKeyDown={(e) => {
          if (e.key === "Escape") setQuery(null);
          if (e.key === "Enter" && matches.length && query !== null) {
            e.preventDefault();
            pick(matches[0]!);
          }
        }}
      />
      <p id={`${id}-hint`} className="ds-rt-meta">Type @ to mention someone. Shown as plain text.</p>
      {matches.length > 0 && (
        <ul id={`${id}-people`} className="ds-note-people" role="listbox" aria-label="People to mention">
          {matches.map((p) => (
            <li key={p.actor} role="option" aria-selected={false}>
              <button type="button" onClick={() => pick(p)}>{p.name} <span className="ds-rt-meta">@{p.handle}</span></button>
            </li>
          ))}
        </ul>
      )}
      {withFiles && (
        <input type="file" multiple aria-label="Attach files" onChange={(e) => setFiles(Array.from(e.target.files ?? []))} />
      )}
      {error && <p role="alert" className="ds-rt-error">{error}</p>}
      <div className="ds-rt-actions">
        {onCancel && <Button type="button" onClick={onCancel}>Cancel</Button>}
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Saving…" : submitLabel}</Button>
      </div>
    </form>
  );
}

export function NotesPanel({ issueId }: { issueId: string }) {
  const fid = useId();
  const [view, setView] = useState<NotesView | null>(null);
  const [people, setPeople] = useState<Person[]>([]);
  const [replyTo, setReplyTo] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    listNotes(issueId).then(
      (v) => setView(Array.isArray(v?.notes) ? v : null),
      (e) => setError(e instanceof ApiError ? e.message : "Could not load notes."),
    );
  }, [issueId]);
  useEffect(load, [load]);
  useEffect(() => {
    listPeople().then((p) => setPeople(Array.isArray(p) ? p : []), () => setPeople([]));
  }, []);
  const handles = useMemo(() => new Set(people.map((p) => p.handle)), [people]);

  async function write(body: string, files: File[], parent?: string) {
    const next = await addNote(issueId, body, parent);
    const mine = [...next.notes].reverse().find((n) => n.author === next.you && n.body === body.trim());
    const failed: string[] = [];
    if (mine) {
      for (const f of files) {
        try {
          await attachToNote(mine.id, f);
        } catch (err) {
          failed.push(`${f.name}: ${err instanceof ApiError ? err.message : "upload failed"}`);
        }
      }
    }
    setError(failed.length ? `Saved, but these files were not attached: ${failed.join("; ")}` : null);
    setReplyTo(null);
    load();
  }

  async function download(id: string) {
    try {
      window.location.assign((await noteFileLink(id)).url);
    } catch {
      setError("Could not get a download link.");
    }
  }

  async function remove(n: Note) {
    try {
      setView(await deleteNote(n.id));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not delete.");
    }
  }

  if (!view) return error ? <p role="alert" className="ds-rt-error">{error}</p> : null;
  const name = (a: string) => view.names[a] ?? a;
  // Threads are a top-level note followed by its replies; a reply box goes after the last of them.
  const endOfThread = replyTo === null ? null : [...view.notes].reverse().find((x) => x.id === replyTo || x.parent_id === replyTo)?.id;

  return (
    <section className="ds-notes ds-issue-section" aria-labelledby={`${fid}-h`}>
      <div className="ds-issue-label" id={`${fid}-h`}>Notes</div>
      {error && <p role="alert" className="ds-rt-error">{error}</p>}
      {view.notes.length === 0 && <p className="ds-rt-meta">No notes yet.</p>}
      <ol className="ds-note-list">
        {view.notes.map((n) => (
          <Fragment key={n.id}>
            <li className={n.parent_id ? "ds-note ds-note-reply" : "ds-note"}>
              <p className="ds-note-head">
                <strong>{name(n.author)}</strong> <time dateTime={n.created_at}>{when(n.created_at)}</time>
                {n.edited_at && !n.deleted && <span className="ds-rt-meta"> (edited)</span>}
              </p>
              {n.deleted ? (
                <p className="ds-note-body ds-rt-meta">Deleted.</p>
              ) : editing === n.id ? (
                <Composer label="Edit note" people={people} initial={n.body} submitLabel="Save"
                  onCancel={() => setEditing(null)}
                  onSubmit={async (body) => { setView(await editNote(n.id, body)); setEditing(null); }} />
              ) : (
                <Body text={n.body} handles={handles} />
              )}
              {n.files.length > 0 && (
                <ul className="ds-note-files">
                  {n.files.map((f) => (
                    <li key={f.id}>
                      <button type="button" className="ds-note-link" onClick={() => download(f.id)}>{f.file_name}</button>{" "}
                      <span className="ds-rt-meta">({Math.ceil(f.size_bytes / 1024)} KB{f.active_content && ", can contain script: download only"})</span>
                    </li>
                  ))}
                </ul>
              )}
              {!n.deleted && editing !== n.id && (
                <div className="ds-note-actions">
                  <button type="button" className="ds-note-link" onClick={() => setReplyTo(n.parent_id ?? n.id)}>Reply</button>
                  {n.author === view.you && (
                    <>
                      <button type="button" className="ds-note-link" onClick={() => setEditing(n.id)}>Edit</button>
                      <ConfirmButton className="ds-note-link" title="Delete this note?" description="Replies to it stay." confirmLabel="Delete" onConfirm={() => remove(n)}>Delete</ConfirmButton>
                    </>
                  )}
                </div>
              )}
            </li>
            {replyTo !== null && n.id === endOfThread && (
              <li className="ds-note ds-note-reply">
                <Composer label="Reply" people={people} submitLabel="Reply" withFiles onCancel={() => setReplyTo(null)}
                  onSubmit={(body, files) => write(body, files, replyTo)} />
              </li>
            )}
          </Fragment>
        ))}
      </ol>
      <Composer label="Add a note" people={people} submitLabel="Add note" withFiles onSubmit={(body, files) => write(body, files)} />
    </section>
  );
}
