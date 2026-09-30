"""core.persistence.repo's get_retention_days/set_retention_days (Week 47 task 2, plan §22.2)."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import DEFAULT_RETENTION_DAYS, Organization
from core.tenancy import DEFAULT_ORG_ID


def test_get_retention_days_defaults_when_no_row_exists(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        assert repo.get_retention_days(s, DEFAULT_ORG_ID) == DEFAULT_RETENTION_DAYS


def test_set_then_get_returns_the_new_value(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_retention_days(s, DEFAULT_ORG_ID, 30)
    with sessions() as s:
        assert repo.get_retention_days(s, DEFAULT_ORG_ID) == 30


def test_set_retention_days_updates_in_place_not_duplicating_rows(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        repo.set_retention_days(s, DEFAULT_ORG_ID, 14)
        repo.set_retention_days(s, DEFAULT_ORG_ID, 21)
    with sessions() as s:
        assert repo.get_retention_days(s, DEFAULT_ORG_ID) == 21


def test_set_retention_days_rejects_less_than_one(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
        s.commit()
        with pytest.raises(ValueError):
            repo.set_retention_days(s, DEFAULT_ORG_ID, 0)
