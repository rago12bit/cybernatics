"""Browser sign-in sessions (Week 75, plan §51; threat T30's "short sessions").

A successful sign-in through the organization's identity provider creates a session. The browser
holds its secret in an HttpOnly cookie; only the secret's SHA-256 is stored, so a copy of the
database cannot be replayed as anyone. A session lasts at most ABSOLUTE and ends after IDLE without
use. It ends at once when the person signs out, is turned off, or is deprovisioned over SCIM.

Changing anything with a session needs its CSRF token in a header as well as the cookie: a page on
another site can make the browser send the cookie, but cannot read the token (it is returned only
to this site's own pages, over CORS, from `GET /auth/session`).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from core.persistence.models import User, UserSession

COOKIE = "bulwark_session"
CSRF_HEADER = "X-Bulwark-CSRF"
ABSOLUTE = timedelta(hours=12)
IDLE = timedelta(hours=2)
TOUCH_EVERY = timedelta(minutes=1)
METHODS = ("oidc", "saml", "test")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def start(
    s: Session, u: User, method: str, user_agent: str | None = None
) -> tuple[str, UserSession]:
    """A new session for `u`; returns the secret (for the cookie, shown nowhere else) and the row.
    Records the sign-in on the user. Not committed."""
    if method not in METHODS:
        raise ValueError(method)
    secret = secrets.token_urlsafe(32)
    now = _now()
    row = UserSession(
        id=digest(secret), org_id=u.org_id, user_id=u.id, method=method,
        csrf=secrets.token_urlsafe(32), created_at=now, last_seen_at=now,
        expires_at=now + ABSOLUTE, user_agent=(user_agent or "")[:200] or None,
    )  # fmt: skip
    s.add(row)
    u.last_login_at = now
    return secret, row


def resolve(s: Session, secret: str | None) -> UserSession | None:
    """The live session this secret belongs to, or None (unknown, revoked, expired, or idle too
    long). Touches it at most once a minute. Read without organization context: `user_sessions`
    has no RLS, since resolving a session is what tells a request its organization."""
    if not secret or len(secret) > 200:
        return None
    row = s.get(UserSession, digest(secret))
    if row is None or row.revoked_at is not None:
        return None
    now = _now()
    if _utc(row.expires_at) <= now or _utc(row.last_seen_at) + IDLE <= now:
        return None
    if now - _utc(row.last_seen_at) >= TOUCH_EVERY:
        row.last_seen_at = now
        s.commit()
    return row


def csrf_ok(row: UserSession, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(row.csrf.encode(), supplied.encode())  # type: ignore[union-attr]


def end(s: Session, secret: str | None) -> bool:
    row = s.get(UserSession, digest(secret)) if secret and len(secret) <= 200 else None
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = _now()
    s.commit()
    return True
