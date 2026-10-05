"""Notes on Issues (plan §49): threaded, with @mentions.

- **Threads are one level deep.** A note is top-level or a reply to a top-level note; a reply to a
  reply attaches to its top-level note, so a thread never nests out of sight.
- **Mentions** (`@handle`, `core.collab.people`) are resolved when the note is written and stored
  as actors; each person mentioned gets an outbox event (`note.mentioned`) and finds the note under
  Mentions. Mentioning yourself does nothing. Editing a note mentions only people newly added.
- **Plain text.** The body is stored and returned as written; the web app renders it as text, never
  as HTML or Markdown.
- **Only the author edits or deletes.** Deleting keeps the row so replies stay in context, blanks
  the body and removes its attachments. Writing, editing and deleting are audit-logged.
- **Attachments** use the evidence store (`core.manual.attachments`): sniffed, encrypted, and
  downloaded only through a short-lived signed link from the attachments origin.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from core.collab.people import Person, people
from core.persistence import repo
from core.persistence.models import Asset, EvidenceAttachment, IssueNote, IssueRow

MAX_BODY = 10_000
MENTION = re.compile(r"(?<![\w@.])@([a-z0-9][a-z0-9._-]{0,63})", re.IGNORECASE)


class NoteError(ValueError):
    def __init__(self, field_name: str, message: str, *, status: int = 422) -> None:
        super().__init__(message)
        self.field = field_name
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def mentioned(body: str, everyone: list[Person]) -> list[str]:
    """Actors whose handle appears as an @mention, in order of first appearance."""
    by_handle: dict[str, list[str]] = defaultdict(list)
    for p in everyone:
        by_handle[p.handle].append(p.actor)
    out: list[str] = []
    for m in MENTION.finditer(body):
        handle = m.group(1).lower().rstrip("._-")
        for actor in by_handle.get(handle, []):
            if actor not in out:
                out.append(actor)
    return out


def _body(raw: str) -> str:
    body = (raw or "").strip()
    if not body:
        raise NoteError("body", "Write something first.")
    if len(body) > MAX_BODY:
        raise NoteError("body", f"A note is at most {MAX_BODY:,} characters.")
    return body


def _announce(s: Session, note: IssueNote, actors: list[str], issue: IssueRow) -> None:
    for actor in actors:
        if actor == note.author:
            continue
        repo.add_outbox_event(
            s, org_id=note.org_id, event_type="note.mentioned",
            payload={"note_id": note.id, "issue_id": note.issue_id, "asset_id": issue.asset_id,
                     "mentioned": actor, "by": note.author},
        )  # fmt: skip


def add(
    s: Session, issue: IssueRow, *, body: str, author: str, parent_id: str | None = None
) -> IssueNote:
    asset = s.get(Asset, issue.asset_id)
    assert asset is not None
    text = _body(body)
    parent = None
    if parent_id is not None:
        parent = s.get(IssueNote, parent_id)
        if parent is None or parent.issue_id != issue.id:
            raise NoteError("parent_id", "That note is not on this issue.", status=404)
        if parent.parent_id is not None:  # keep threads one level deep
            parent = s.get(IssueNote, parent.parent_id)
    who = mentioned(text, people(s, asset.org_id))
    note = IssueNote(
        org_id=asset.org_id, issue_id=issue.id, parent_id=parent.id if parent else None,
        body=text, author=author, mentions=who,
    )  # fmt: skip
    s.add(note)
    s.flush()
    _announce(s, note, who, issue)
    repo.append_audit_entry(  # commits
        s, actor=author, action="issue.note.added", target=issue.id,
        payload={"note_id": note.id, "mentions": who},
    )  # fmt: skip
    return note


def _own(note: IssueNote, actor: str) -> None:
    if note.deleted_at is not None:
        raise NoteError("note", "That note was deleted.", status=409)
    if note.author != actor:
        raise NoteError("note", "Only its author can change a note.", status=403)


def edit(s: Session, note: IssueNote, *, body: str, actor: str) -> IssueNote:
    _own(note, actor)
    text = _body(body)
    asset_issue = s.get(IssueRow, note.issue_id)
    assert asset_issue is not None
    who = mentioned(text, people(s, note.org_id))
    new = [a for a in who if a not in (note.mentions or [])]
    note.body, note.mentions, note.edited_at = text, who, _now()
    s.flush()
    _announce(s, note, new, asset_issue)
    repo.append_audit_entry(
        s, actor=actor, action="issue.note.edited", target=note.issue_id,
        payload={"note_id": note.id, "new_mentions": new},
    )  # fmt: skip
    return note


def remove(s: Session, note: IssueNote, *, actor: str) -> IssueNote:
    _own(note, actor)
    note.body, note.deleted_at = "", _now()
    s.execute(delete(EvidenceAttachment).where(EvidenceAttachment.note_id == note.id))
    s.flush()
    repo.append_audit_entry(
        s, actor=actor, action="issue.note.deleted", target=note.issue_id,
        payload={"note_id": note.id},
    )  # fmt: skip
    return note


def get(s: Session, note_id: str, org_id: str) -> IssueNote | None:
    return s.scalars(
        select(IssueNote).where(IssueNote.id == note_id, IssueNote.org_id == org_id)
    ).one_or_none()


def thread(s: Session, issue_id: str) -> list[IssueNote]:
    """Top-level notes oldest first, each followed by its replies oldest first."""
    rows = list(
        s.scalars(
            select(IssueNote).where(IssueNote.issue_id == issue_id).order_by(IssueNote.created_at)
        )
    )
    replies: dict[str, list[IssueNote]] = defaultdict(list)
    for n in rows:
        if n.parent_id:
            replies[n.parent_id].append(n)
    out: list[IssueNote] = []
    for n in rows:
        if n.parent_id is None:
            out.append(n)
            out.extend(replies[n.id])
    return out


def attachments_of(s: Session, note_ids: list[str]) -> dict[str, list[EvidenceAttachment]]:
    out: dict[str, list[EvidenceAttachment]] = defaultdict(list)
    if note_ids:
        for a in s.scalars(
            select(EvidenceAttachment)
            .where(EvidenceAttachment.note_id.in_(note_ids))
            .order_by(EvidenceAttachment.created_at)
        ):
            out[a.note_id or ""].append(a)
    return out


def mentions_of(s: Session, org_id: str, actor: str, limit: int = 100) -> list[dict[str, Any]]:
    """Notes that mention `actor`, newest first, with the Issue they are on."""
    rows = s.execute(
        select(IssueNote, IssueRow)
        .join(IssueRow, IssueRow.id == IssueNote.issue_id)
        .where(IssueNote.org_id == org_id, IssueNote.deleted_at.is_(None))
        .order_by(IssueNote.created_at.desc())
    )
    out = []
    for note, issue in rows:
        if actor in (note.mentions or []):
            out.append({"note": note, "issue": issue})
            if len(out) >= limit:
                break
    return out
