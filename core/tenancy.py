"""Multi-tenancy primitives (ADR-0013). Deliberately tiny: this module only names the concepts that
`core/persistence/models.py`, `core/persistence/repo.py`, `api/deps.py` and the tenancy migration
all need to agree on, so they don't each invent their own constant.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from core.persistence.db import SessionFactory

#: Every pre-Week-29 row (and every row created by a caller that doesn't specify an org) belongs to
#: this bootstrap organization. Fixed and well-known on purpose: a self-hosted, single-tenant
#: deployment never has to know tenancy exists, and every existing test's `repo.create_scan(...)`
#: call (no `org_id` kwarg) keeps working unchanged.
DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000000"

#: The Postgres session variable Row-Level Security policies read via `current_setting(...)`. Set
#: per-request with `set_config(CURRENT_ORG_SETTING, org_id, true)` (the `true` = local to the
#: transaction) rather than a hand-built `SET LOCAL` string, so the client-supplied org id is always
#: a bound parameter, never concatenated into SQL text.
CURRENT_ORG_SETTING = "app.current_org"

#: The header a caller uses to select an organization. There is no real per-organization identity
#: yet (that's the plan's §19.2: GitHub sign-in / passkeys / TOTP) — v1's single shared bearer token
#: still authenticates *that* a caller may use the API at all, and this header only selects *which*
#: org's data the request should see. A caller that knows the token can claim any org id. That is a
#: known, explicit limitation of this week's scope, not an oversight: it proves the isolation
#: plumbing (RLS + app-level filtering) is correct, and real org membership binds to it later
#: without changing the isolation mechanism itself.
ORG_HEADER = "X-Bulwark-Org"


def set_session_org(s: Session, org_id: str) -> None:
    """Set `app.current_org` on an already-open session, for the rest of its life (session-scoped,
    not transaction-local -- see `api.deps.db`'s docstring for why `true`/local breaks the moment a
    caller commits more than once in one session, which several `repo.py` functions do). A no-op on
    SQLite, which has no RLS to set up in the first place.

    Shared by every place that establishes org context for a session: `api.deps.db` (from the
    request's `X-Bulwark-Org` header), `scoped_sessions` below (from a worker task's payload), and
    the GitHub webhook handler (from a *resolved* installation -> org mapping, only knowable
    after looking one up -- see `core.persistence.repo.get_or_create_installation`'s docstring for
    why that lookup itself must not be RLS-gated)."""
    if s.bind is not None and s.bind.dialect.name == "postgresql":
        s.execute(
            text("SELECT set_config(:key, :org, false)"),
            {"key": CURRENT_ORG_SETTING, "org": org_id},
        )


def scoped_sessions(factory: SessionFactory, org_id: str) -> SessionFactory:
    """Wrap a session factory so every session it opens has `app.current_org` set for `org_id`
    before the caller runs anything else on it. Mirrors `api.deps.db` for the worker, which has no
    FastAPI dependency injection to do this for it -- without it, the worker (which connects as the
    same non-superuser role the API does, ADR-0013) would have every write silently rejected or
    dropped by Row-Level Security, since it would never identify which org it's acting for.

    The caller learns `org_id` from the task payload (set at enqueue time, when the API already
    knows it), not by reading it back from the database first: the worker has no bypass privilege,
    so it cannot `SELECT` a scan's own `org_id` before it has already set one, and there is nothing
    else it could safely default to."""

    def _open() -> Session:
        s = factory()
        set_session_org(s, org_id)
        return s

    return _open
