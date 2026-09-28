"""`bulwark token` and `bulwark audit` (Week 29/30 backfill), against a real SQLite DB via the CLI's
own session factory -- the same isolation pattern `test_rag.py::test_kb_cli_load_stats_and_search`
uses.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from typer.testing import CliRunner

import core.persistence.db as db
from cli.main import app
from core.persistence.models import Base, Organization

runner = CliRunner()


@pytest.fixture
def cli_db(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Organization(id="org-a", name="Org A"))
        s.commit()
    monkeypatch.setattr(db, "get_session_factory", lambda: (lambda: Session(engine)))
    return engine


def test_token_create_prints_the_raw_token_once_and_never_again(cli_db) -> None:  # type: ignore[no-untyped-def]
    r = runner.invoke(
        app, ["token", "create", "--org-id", "org-a", "--name", "ci", "--scope", "scans:read"]
    )
    assert r.exit_code == 0
    assert "bulwark_" in r.output
    assert "shown once" in r.output


def test_token_create_rejects_an_unknown_scope(cli_db) -> None:  # type: ignore[no-untyped-def]
    r = runner.invoke(
        app, ["token", "create", "--org-id", "org-a", "--name", "ci", "--scope", "sudo:everything"]
    )
    assert r.exit_code == 1
    assert "unknown scope" in r.output


def test_token_list_and_revoke_round_trip(cli_db) -> None:  # type: ignore[no-untyped-def]
    runner.invoke(
        app, ["token", "create", "--org-id", "org-a", "--name", "laptop", "--scope", "scans:read"]
    )
    listed = json.loads(runner.invoke(app, ["token", "list", "--org-id", "org-a"]).output)
    assert len(listed) == 1 and listed[0]["name"] == "laptop" and listed[0]["revoked_at"] is None
    revoked = runner.invoke(app, ["token", "revoke", listed[0]["id"]])
    assert revoked.exit_code == 0
    listed_again = json.loads(runner.invoke(app, ["token", "list", "--org-id", "org-a"]).output)
    assert listed_again[0]["revoked_at"] is not None


def test_revoking_an_unknown_token_id_is_a_clean_error(cli_db) -> None:  # type: ignore[no-untyped-def]
    r = runner.invoke(app, ["token", "revoke", "not-a-real-id"])
    assert r.exit_code == 1


def test_audit_verify_on_an_empty_log_is_ok(cli_db) -> None:  # type: ignore[no-untyped-def]
    r = runner.invoke(app, ["audit", "verify"])
    assert r.exit_code == 0
    out = json.loads(r.output)
    assert out["chain_ok"] is True and out["entries_checked"] == 0


def test_creating_and_revoking_a_token_extends_the_verifiable_chain(cli_db) -> None:  # type: ignore[no-untyped-def]
    runner.invoke(
        app, ["token", "create", "--org-id", "org-a", "--name", "ci", "--scope", "scans:read"]
    )
    listed = json.loads(runner.invoke(app, ["token", "list", "--org-id", "org-a"]).output)
    runner.invoke(app, ["token", "revoke", listed[0]["id"]])
    out = json.loads(runner.invoke(app, ["audit", "verify"]).output)
    assert out["chain_ok"] is True and out["entries_checked"] == 2  # created + revoked


def test_audit_verify_fails_loudly_when_the_chain_is_tampered(cli_db) -> None:  # type: ignore[no-untyped-def]
    from core.persistence import repo
    from core.persistence.models import AuditEntry

    with Session(cli_db) as s:
        repo.append_audit_entry(s, actor="t", action="a", target="1", payload={})
        row = s.query(AuditEntry).one()
        row.action = "tampered"
        s.commit()
    r = runner.invoke(app, ["audit", "verify"])
    assert r.exit_code == 1
    out = json.loads(r.output)
    assert out["chain_ok"] is False and out["broken_at_seq"] == 1


def test_audit_checkpoint_dry_run_touches_nothing(cli_db) -> None:  # type: ignore[no-untyped-def]
    from core.persistence import repo

    with Session(cli_db) as s:
        repo.append_audit_entry(s, actor="t", action="a", target="1", payload={})
    r = runner.invoke(app, ["audit", "checkpoint", "--key", "/nonexistent.key", "--dry-run"])
    assert r.exit_code == 0
    assert "would_checkpoint_seq" in r.output
    with Session(cli_db) as s:
        assert repo.list_checkpoints(s) == []


def test_audit_checkpoint_on_an_empty_log_is_a_no_op(cli_db) -> None:  # type: ignore[no-untyped-def]
    r = runner.invoke(app, ["audit", "checkpoint", "--key", "/nonexistent.key"])
    assert r.exit_code == 0
    assert "nothing to checkpoint" in r.output
