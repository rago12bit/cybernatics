"""`bulwark asset add-web` and `bulwark asset link-source`, against a real SQLite DB via the CLI's
own session factory (the pattern `test_token_audit_cli.py` uses)."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from typer.testing import CliRunner

import core.persistence.db as db
from cli.main import app
from core.persistence import repo
from core.persistence.models import Asset, AssetVerification, Base, Organization

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


def test_a_web_targets_source_is_linked_changed_and_cleared_after_registration(cli_db) -> None:  # type: ignore[no-untyped-def]
    with Session(cli_db) as s:
        code = repo.get_or_create_asset(s, source_type="git", source_label="https://g/a/b",
                                        org_id="org-a")  # fmt: skip
        s.commit()
        code_id = code.id
    added = runner.invoke(app, ["asset", "add-web", "example.com", "--org", "org-a"])
    assert added.exit_code == 0, added.output
    site = json.loads(added.output)["asset_id"]
    with Session(cli_db) as s:
        token = s.get(AssetVerification, site).token  # type: ignore[union-attr]

    linked = runner.invoke(app, ["asset", "link-source", site, "--source-asset-id", code_id,
                                 "--org", "org-a"])  # fmt: skip
    assert linked.exit_code == 0, linked.output
    assert json.loads(linked.output) == {"asset_id": site, "source_asset_id": code_id}
    with Session(cli_db) as s:
        assert s.get(Asset, site).linked_source_asset_id == code_id  # type: ignore[union-attr]
        assert s.get(AssetVerification, site).token == token  # type: ignore[union-attr]

    cleared = runner.invoke(app, ["asset", "link-source", site, "--clear", "--org", "org-a"])
    assert cleared.exit_code == 0, cleared.output
    with Session(cli_db) as s:
        assert s.get(Asset, site).linked_source_asset_id is None  # type: ignore[union-attr]

    both = runner.invoke(app, ["asset", "link-source", site, "--clear", "--source-asset-id",
                               code_id, "--org", "org-a"])  # fmt: skip
    neither = runner.invoke(app, ["asset", "link-source", site, "--org", "org-a"])
    wrong_way = runner.invoke(app, ["asset", "link-source", code_id, "--source-asset-id", site,
                                    "--org", "org-a"])  # fmt: skip
    assert both.exit_code == neither.exit_code == wrong_way.exit_code == 1
    assert "only a web target" in wrong_way.output
