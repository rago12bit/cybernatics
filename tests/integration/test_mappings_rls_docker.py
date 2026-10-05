"""Saved import mappings under REAL Row-Level Security (migration 0030, Week 59, ADR-0043): another
org can neither list, read, version nor import with a mapping it does not own, and cannot write one
labelled as another org's. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as
`bulwark_worker`)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from core.imports import mapper
from core.imports.parsers.universal import MappingSpec
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401

SPEC = MappingSpec.from_dict(
    {"format": "json", "source": "acme", "records": "$[*]", "fields": {"title": "$.t"}}
)


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:  # noqa: F811
    a, b = f"map-a-{uuid.uuid4().hex[:8]}", f"map-b-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
            [{"id": a, "n": "A"}, {"id": b, "n": "B"}],
        )
        s.commit()
    yield a, b
    with sessions() as s:
        for org in (a, b):
            set_session_org(s, org)
            s.execute(text("DELETE FROM ingest_mappings WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def test_another_org_cannot_see_or_resolve_a_mapping(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        row = mapper.save_mapping(s, org_id=a, name="Acme", spec=SPEC)
        mapper.save_mapping(s, org_id=a, name="Acme", spec=SPEC)
        s.commit()
        mapping_id = row.id
    with sessions() as s:
        set_session_org(s, b)
        assert mapper.list_mappings(s, b) == [] and mapper.versions(s, b, "Acme") == []
        assert mapper.get_mapping(s, mapping_id, a) is None  # even naming the right org id
        with pytest.raises(ValueError, match="unknown mapping"):
            mapper.resolve(s, b, mapper.parser_name(mapping_id))
        # Org B's own "Acme" starts at version 1: versions are per org, not global.
        assert mapper.save_mapping(s, org_id=b, name="Acme", spec=SPEC).version == 1
        s.commit()
    with sessions() as s:
        set_session_org(s, a)
        assert [m.version for m in mapper.versions(s, a, "Acme")] == [2, 1]
        parser, spec = mapper.resolve(s, a, mapper.parser_name(mapping_id))
        assert spec == SPEC.to_dict() and parser.name == mapper.parser_name(mapping_id)


def test_another_org_cannot_write_a_mapping_labelled_as_someone_elses(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, b)
        with pytest.raises(DBAPIError):  # org B's policy refuses a row labelled org A
            mapper.save_mapping(s, org_id=a, name="Planted", spec=SPEC)
            s.commit()
