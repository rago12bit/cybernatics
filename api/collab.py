"""Collaboration API (Week 64, plan §49): notes with @mentions, files on notes, tags, portfolios.

    GET    /v2/people                         who can be @mentioned or named (personal API tokens)
    GET    /v2/issues/{id}/notes              the Issue's notes, threaded
    POST   /v2/issues/{id}/notes              write a note or a reply
    PATCH  /v2/notes/{id}                     edit your note        DELETE /v2/notes/{id}
    POST   /v2/notes/{id}/attachments         attach a file to your note
    POST   /v2/note-attachments/{id}/link     a short-lived download link, on the attachments origin
    GET    /v2/mentions                       notes that mention you
    GET    /v2/issues/{id}/tags               own and inherited tags   PUT: set its own
    GET    /v2/projects/{id}/tags             own and inherited tags   PUT: set its own
    PUT    /v2/projects/{id}/portfolio        put the project in a portfolio (or none)
    GET    /v2/portfolios                     POST: create one;  PUT /v2/portfolios/{id}/tags

Reading is `scans:read`; writing is `scans:write`; every change is audit-logged.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from api.retest import issue_for
from core.collab import notes, tags
from core.collab.people import names, people
from core.manual import attachments
from core.persistence import repo
from core.persistence.models import EvidenceAttachment, IssueNote

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class PersonOut(BaseModel):
    actor: str
    name: str
    handle: str


class FileOut(BaseModel):
    id: str
    file_name: str
    sniffed_type: str
    active_content: bool
    size_bytes: int
    encrypted: bool


class NoteOut(BaseModel):
    id: str
    issue_id: str
    parent_id: str | None
    body: str = Field(description="Plain text, as written. Empty once deleted.")
    author: str
    mentions: list[str]
    created_at: datetime
    edited_at: datetime | None
    deleted: bool
    files: list[FileOut]


class NotesOut(BaseModel):
    notes: list[NoteOut]
    names: dict[str, str]
    you: str


class NoteIn(BaseModel):
    body: str = Field(max_length=10_000)
    parent_id: str | None = None


class NoteEdit(BaseModel):
    body: str = Field(max_length=10_000)


class MentionOut(BaseModel):
    note: NoteOut
    issue_title: str
    project_id: str


class MentionsOut(BaseModel):
    mentions: list[MentionOut]
    names: dict[str, str]


class InheritedTag(BaseModel):
    name: str
    from_: str = Field(alias="from", description="portfolio or project")
    source: str

    model_config = {"populate_by_name": True}


class TagsOut(BaseModel):
    own: list[str]
    inherited: list[InheritedTag]
    portfolio: dict[str, str] | None = None


class TagsIn(BaseModel):
    tags: list[str] = Field(max_length=20)


class PortfolioIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class PortfolioOut(BaseModel):
    id: str
    name: str
    description: str | None
    tags: list[str]


class AssignIn(BaseModel):
    portfolio_id: str | None


class LinkOut(BaseModel):
    url: str
    expires_at: datetime


def _file(a: EvidenceAttachment) -> FileOut:
    return FileOut(
        id=a.id, file_name=a.file_name, sniffed_type=a.sniffed_type,
        active_content=a.active_content, size_bytes=a.size_bytes, encrypted=a.encrypted,
    )  # fmt: skip


def _note(n: IssueNote, files: list[EvidenceAttachment]) -> NoteOut:
    return NoteOut(
        id=n.id, issue_id=n.issue_id, parent_id=n.parent_id, body=n.body, author=n.author,
        mentions=list(n.mentions or []), created_at=n.created_at, edited_at=n.edited_at,
        deleted=n.deleted_at is not None, files=[_file(f) for f in files],
    )  # fmt: skip


def _note_error(exc: notes.NoteError) -> HTTPException:
    return HTTPException(exc.status, {"field": exc.field, "message": str(exc)})


def _tag_error(exc: tags.TagError) -> HTTPException:
    return HTTPException(422, {"field": exc.field, "message": str(exc)})


def _my_note(s: Session, note_id: str, org: str) -> IssueNote:
    n = notes.get(s, note_id, org) if _UUID.match(note_id) else None
    if n is None:
        raise HTTPException(404, "note not found")
    return n


def _project(s: Session, project_id: str, org: str) -> Any:
    a = repo.get_asset(s, project_id, org_id=org) if _UUID.match(project_id) else None
    if a is None:
        raise HTTPException(404, "project not found")
    return a


def register_collab_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/people",
        response_model=list[PersonOut],
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_people(s: Session = Depends(db), org: str = Depends(current_org)) -> list[PersonOut]:
        return [PersonOut(actor=p.actor, name=p.name, handle=p.handle) for p in people(s, org)]

    # --- notes ------------------------------------------------------------------------------------

    def _thread(s: Session, issue_id: str, org: str, you: str) -> NotesOut:
        rows = notes.thread(s, issue_id)
        files = notes.attachments_of(s, [n.id for n in rows])
        actors = {n.author for n in rows} | {a for n in rows for a in (n.mentions or [])}
        return NotesOut(
            notes=[_note(n, files.get(n.id, [])) for n in rows],
            names=names(s, org, actors | {you}),
            you=you,
        )

    @app.get(
        "/v2/issues/{issue_id}/notes",
        response_model=NotesOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_notes(
        issue_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> NotesOut:
        issue = issue_for(s, issue_id, org)
        return _thread(s, issue.id, org, auth.actor)

    @app.post(
        "/v2/issues/{issue_id}/notes",
        response_model=NotesOut,
        status_code=201,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def add_note(
        issue_id: str,
        body: NoteIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> NotesOut:
        issue = issue_for(s, issue_id, org)
        parent = body.parent_id if body.parent_id and _UUID.match(body.parent_id) else None
        if body.parent_id and parent is None:
            raise HTTPException(404, {"field": "parent_id", "message": "That note is not here."})
        try:
            notes.add(s, issue, body=body.body, author=auth.actor, parent_id=parent)
        except notes.NoteError as exc:
            s.rollback()
            raise _note_error(exc) from exc
        return _thread(s, issue.id, org, auth.actor)

    @app.patch(
        "/v2/notes/{note_id}",
        response_model=NotesOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def edit_note(
        note_id: str,
        body: NoteEdit,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> NotesOut:
        n = _my_note(s, note_id, org)
        try:
            notes.edit(s, n, body=body.body, actor=auth.actor)
        except notes.NoteError as exc:
            s.rollback()
            raise _note_error(exc) from exc
        return _thread(s, n.issue_id, org, auth.actor)

    @app.delete(
        "/v2/notes/{note_id}",
        response_model=NotesOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def delete_note(
        note_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> NotesOut:
        n = _my_note(s, note_id, org)
        try:
            notes.remove(s, n, actor=auth.actor)
        except notes.NoteError as exc:
            s.rollback()
            raise _note_error(exc) from exc
        return _thread(s, n.issue_id, org, auth.actor)

    @app.post(
        "/v2/notes/{note_id}/attachments",
        response_model=FileOut,
        status_code=201,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def add_note_file(
        note_id: str,
        file: UploadFile = File(...),
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> FileOut:
        n = _my_note(s, note_id, org)
        if n.author != auth.actor or n.deleted_at is not None:
            raise HTTPException(403, "only its author can attach files to a note")
        data = file.file.read(attachments.MAX_BYTES + 1)
        try:
            stored = attachments.store(
                s, note=n, data=data, file_name=file.filename, declared_type=file.content_type,
                created_by=auth.actor, openbao_addr=st.settings.openbao_addr,
                openbao_token=st.settings.openbao_token,
            )  # fmt: skip
        except attachments.AttachmentError as exc:
            s.rollback()
            raise HTTPException(413 if "10 MB" in str(exc) else 422, str(exc)) from exc
        return _file(stored)

    @app.post(
        "/v2/note-attachments/{attachment_id}/link",
        response_model=LinkOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def note_file_link(
        attachment_id: str,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> LinkOut:
        row = attachments.get(s, attachment_id, org) if _UUID.match(attachment_id) else None
        if row is None or row.note_id is None:
            raise HTTPException(404, "attachment not found")
        token, expires = attachments.sign(attachments.link_key(st.settings.api_token), row.id, org)
        return LinkOut(
            url=f"{st.settings.attachments_origin}/v2/attachments/{row.id}/download?token={token}",
            expires_at=datetime.fromtimestamp(expires, tz=timezone.utc),
        )

    @app.get(
        "/v2/mentions",
        response_model=MentionsOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def my_mentions(
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> MentionsOut:
        found = notes.mentions_of(s, org, auth.actor)
        actors = {m["note"].author for m in found}
        return MentionsOut(
            mentions=[
                MentionOut(note=_note(m["note"], []), issue_title=m["issue"].title,
                           project_id=m["issue"].asset_id)  # fmt: skip
                for m in found
            ],
            names=names(s, org, actors),
        )

    # --- tags and portfolios ----------------------------------------------------------------------

    @app.get(
        "/v2/issues/{issue_id}/tags",
        response_model=TagsOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def issue_tags(
        issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        return tags.for_issue(s, issue_for(s, issue_id, org))

    @app.put(
        "/v2/issues/{issue_id}/tags",
        response_model=TagsOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def set_issue_tags(
        issue_id: str,
        body: TagsIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        issue = issue_for(s, issue_id, org)
        try:
            tags.replace(s, org_id=org, target_type="issue", target_id=issue.id, names=body.tags,
                         actor=auth.actor)  # fmt: skip
        except tags.TagError as exc:
            s.rollback()
            raise _tag_error(exc) from exc
        return tags.for_issue(s, issue)

    @app.get(
        "/v2/projects/{project_id}/tags",
        response_model=TagsOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def project_tags(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        return tags.for_project(s, _project(s, project_id, org))

    @app.put(
        "/v2/projects/{project_id}/tags",
        response_model=TagsOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def set_project_tags(
        project_id: str,
        body: TagsIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        asset = _project(s, project_id, org)
        try:
            tags.replace(s, org_id=org, target_type="project", target_id=asset.id,
                         names=body.tags, actor=auth.actor)  # fmt: skip
        except tags.TagError as exc:
            s.rollback()
            raise _tag_error(exc) from exc
        return tags.for_project(s, asset)

    @app.put(
        "/v2/projects/{project_id}/portfolio",
        response_model=TagsOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def assign_portfolio(
        project_id: str,
        body: AssignIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        asset = _project(s, project_id, org)
        pid = body.portfolio_id if body.portfolio_id and _UUID.match(body.portfolio_id) else None
        if body.portfolio_id and pid is None:
            raise HTTPException(422, {"field": "portfolio_id", "message": "No such portfolio."})
        try:
            tags.set_portfolio(s, asset, pid, org_id=org, actor=auth.actor)
        except tags.TagError as exc:
            s.rollback()
            raise HTTPException(422, {"field": "portfolio_id", "message": str(exc)}) from exc
        s.commit()
        return tags.for_project(s, asset)

    @app.get(
        "/v2/portfolios",
        response_model=list[PortfolioOut],
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_portfolios(
        s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[PortfolioOut]:
        return [
            PortfolioOut(id=p.id, name=p.name, description=p.description,
                         tags=tags.own(s, "portfolio", p.id))  # fmt: skip
            for p in repo.list_portfolios(s, org)
        ]

    @app.post(
        "/v2/portfolios",
        response_model=PortfolioOut,
        status_code=201,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def create_portfolio(
        body: PortfolioIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> PortfolioOut:
        name = " ".join(body.name.split())
        if not name:
            raise HTTPException(422, {"field": "name", "message": "Name the portfolio."})
        p = repo.create_portfolio(s, org_id=org, name=name, description=body.description)
        repo.append_audit_entry(
            s, actor=auth.actor, action="portfolio.created", target=f"portfolio:{p.id}",
            payload={"org_id": org, "name": name},
        )  # fmt: skip
        return PortfolioOut(id=p.id, name=p.name, description=p.description, tags=[])

    @app.put(
        "/v2/portfolios/{portfolio_id}/tags",
        response_model=PortfolioOut,
        tags=["collaboration"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def set_portfolio_tags(
        portfolio_id: str,
        body: TagsIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> PortfolioOut:
        p = repo.get_portfolio(s, portfolio_id, org) if _UUID.match(portfolio_id) else None
        if p is None:
            raise HTTPException(404, "portfolio not found")
        try:
            names_ = tags.replace(s, org_id=org, target_type="portfolio", target_id=p.id,
                                  names=body.tags, actor=auth.actor)  # fmt: skip
        except tags.TagError as exc:
            s.rollback()
            raise _tag_error(exc) from exc
        return PortfolioOut(id=p.id, name=p.name, description=p.description, tags=names_)
