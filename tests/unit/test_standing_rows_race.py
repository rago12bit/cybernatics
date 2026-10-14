"""Two transactions creating the same project, standing engagement or Test at once (migration 0052).

Each test lets the first lookup find nothing, then has a second session create and commit the same
row before this one inserts -- what happens when two first scans of a repository, or two uploads to
a new project, run together. The loser must use the winner's row, not fail and not duplicate it.
The real thing, with two threads on Postgres, is in
tests/integration/test_standing_rows_race_rls_docker.py."""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import (
    Asset,
    Engagement,
    EngagementChecklistItem,
    EngagementTest,
    Organization,
    Scan,
    ToolRun,
)
from core.tenancy import DEFAULT_ORG_ID as ORG


def _org(s: Session) -> None:
    s.add(Organization(id=ORG, name="default"))
    s.commit()


def _lose_the_race(
    monkeypatch: pytest.MonkeyPatch,
    sessions: sessionmaker[Session],
    winner: Callable[[Session], Any],
) -> list[Any]:
    """Just before this session inserts, another one creates the same row and commits."""
    real = repo._add_unless_taken
    won: list[Any] = []
    racing_now: list[bool] = []

    def racing(s: Session, row: Any, found: Any) -> Any:
        if not racing_now:  # the other session's own insert goes straight through
            racing_now.append(True)
            with sessions() as other:
                won.append(winner(other).id)
        return real(s, row, found)

    monkeypatch.setattr(repo, "_add_unless_taken", racing)
    return won


def _count(s: Session, model: Any, *where: Any) -> int:
    return int(s.scalar(select(func.count()).select_from(model).where(*where)) or 0)


def test_a_scan_that_loses_the_race_uses_the_project_the_other_created(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    with sessions() as s:
        _org(s)
    won = _lose_the_race(monkeypatch, sessions, lambda o: repo.get_or_create_asset(
        o, source_type="git", source_label="https://github.com/a/b", org_id=ORG))  # fmt: skip
    with sessions() as s:
        asset = repo.get_or_create_asset(
            s, source_type="git", source_label="https://github.com/a/b.git", org_id=ORG
        )
        assert asset.id == won[0]
        assert asset.label == "https://github.com/a/b.git"  # refreshed, as for any existing one
        assert asset.last_scanned_at is not None
        assert _count(s, Asset) == 1
        # and the session is usable: the scan goes on to be created
        scan = repo.create_scan(s, source_type="git", source_ref="x",
                                source_label="https://github.com/a/b", tools=[], org_id=ORG)  # fmt: skip
        assert scan.asset_id == asset.id


@pytest.mark.parametrize("kind", ["ci", "import"])
def test_one_standing_engagement_when_two_create_it_at_once(
    kind: str, sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    get = getattr(repo, f"get_or_create_{kind}_engagement")
    with sessions() as s:
        _org(s)
        asset_id = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=ORG).id
    won = _lose_the_race(monkeypatch, sessions, lambda o: get(o, asset_id=asset_id, org_id=ORG))
    with sessions() as s:
        assert get(s, asset_id=asset_id, org_id=ORG).id == won[0]
        assert _count(s, Engagement, Engagement.engagement_type == kind) == 1


def test_one_test_when_two_uploads_create_it_at_once(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    with sessions() as s:
        _org(s)
        asset_id = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=ORG).id
        eng = repo.get_or_create_import_engagement(s, asset_id=asset_id, org_id=ORG).id
    won = _lose_the_race(monkeypatch, sessions, lambda o: repo.get_or_create_engagement_test(
        o, org_id=ORG, engagement_id=eng, name="Nessus"))  # fmt: skip
    with sessions() as s:
        test = repo.get_or_create_engagement_test(s, org_id=ORG, engagement_id=eng, name="Nessus")
        assert test.id == won[0]
        assert _count(s, EngagementTest) == 1


def test_any_other_integrity_error_is_raised(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        _org(s)
        found = select(Asset).where(Asset.key == "nothing")
        with pytest.raises(IntegrityError):
            repo._add_unless_taken(s, Asset(org_id=ORG, source_type="git", key=None), found)


def test_the_database_allows_one_standing_engagement_and_any_number_of_assessments(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _org(s)
        asset_id = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=ORG).id
        for _ in range(2):
            repo.create_engagement(s, org_id=ORG, asset_id=asset_id, name="Q3",
                                   engagement_type="assessment")  # fmt: skip
        repo.get_or_create_ci_engagement(s, asset_id=asset_id, org_id=ORG)
        s.add(Engagement(org_id=ORG, asset_id=asset_id, name="again", engagement_type="ci"))
        with pytest.raises(IntegrityError):
            s.commit()


# --- migration 0052: duplicates made before the index ------------------------------------------


def _migration() -> Any:
    path = Path(__file__).parents[2] / "migrations/versions/0052_one_standing_engagement.py"
    spec = importlib.util.spec_from_file_location("m0052", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _duplicates(s: Session) -> tuple[str, str, str]:
    """A project with two "import" engagements (each with a "Nessus" Test, the second also a
    "Burp" one) and two "ci" ones (each with a tool run), as the race could leave them."""
    s.execute(text("DROP INDEX uq_engagements_standing"))
    _org(s)
    asset_id = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=ORG).id
    scan = Scan(org_id=ORG, source_type="git", source_ref="x", source_label="a/b", tools=[],
                asset_id=asset_id, status="completed")  # fmt: skip
    s.add(scan)
    s.flush()
    first: dict[str, str] = {}
    for n in range(2):
        for kind in ("import", "ci"):
            e = Engagement(org_id=ORG, asset_id=asset_id, name=f"{kind} {n}", engagement_type=kind)
            s.add(e)
            s.flush()
            first.setdefault(kind, e.id)
            if kind == "import":
                s.add(EngagementTest(org_id=ORG, engagement_id=e.id, name="Nessus"))
                if n == 1:
                    s.add(EngagementTest(org_id=ORG, engagement_id=e.id, name="Burp"))
            else:
                s.add(ToolRun(scan_id=scan.id, tool=f"t{n}", status="ok", engagement_id=e.id))
        s.commit()
    return asset_id, first["import"], first["ci"]


def test_migration_0052_merges_duplicates_into_the_oldest(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, keep_import, keep_ci = _duplicates(s)
        _migration()._merge_duplicates(s.connection())
        s.commit()
        engagements = {e.engagement_type: e.id for e in s.scalars(select(Engagement))}
        assert engagements == {"import": keep_import, "ci": keep_ci}
        assert _count(s, Engagement) == 2
        runs = list(s.scalars(select(ToolRun)))
        assert {r.engagement_id for r in runs} == {keep_ci} and len(runs) == 2
        names = sorted(t.name for t in s.scalars(select(EngagementTest)))
        assert len(names) == 3 and names[:2] == ["Burp", "Nessus"]
        assert names[2].startswith("Nessus (merged ")  # kept, beside the other, not folded in
        assert {t.engagement_id for t in s.scalars(select(EngagementTest))} == {keep_import}
        # the index can now be created
        s.execute(text("CREATE UNIQUE INDEX uq_engagements_standing ON engagements "
                       "(asset_id, engagement_type) WHERE engagement_type IN ('ci', 'import')"))  # fmt: skip


def test_migration_0052_stops_rather_than_delete_checklist_entries(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, keep_import, _ = _duplicates(s)
        dup = s.scalars(select(Engagement.id).where(Engagement.engagement_type == "import",
                                                    Engagement.id != keep_import)).one()  # fmt: skip
        s.add(EngagementChecklistItem(org_id=ORG, engagement_id=dup, item_id="WSTG-INFO-01",
                                      status="passed"))  # fmt: skip
        s.commit()
        with pytest.raises(RuntimeError, match="checklist"):
            _migration()._merge_duplicates(s.connection())
