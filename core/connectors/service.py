"""Connectors: configuring them, running them, and saying how they are (plan §42.5, §55.7 "Connector
health. Each connector's last success, items fetched, and a warning when it connects but fetches
nothing", ADR-0045).

A pull is the source's complete current list, applied through `core.imports.service.apply_import`
into the connector's Test with `close_missing`: what the source no longer lists is closed here.
That makes two failure modes dangerous, and both are handled before anything is applied:

- **A partial pull** (a page failed, too many pages) is an error, never applied.
- **An empty pull after a non-empty one** is held back: "everything was fixed at once" and "the
  credential lost access" look the same from here, so nothing is closed unless the connector has
  `close_on_empty`. The run is recorded as `empty`, with a warning saying so.

An unchanged pull is the same file as last time (same digest), which the ingest path already
treats as a no-op; a run records the counts either way.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.config import Settings
from core.connectors import defectdojo, github, gitlab
from core.connectors.base import Fetched
from core.connectors.http import ConnectorError, Transport, check_url, http_transport
from core.imports import service as imports
from core.imports.prepare import prepare
from core.persistence import repo
from core.persistence.models import (
    Connector,
    ConnectorRun,
    FindingRow,
    GithubInstallation,
    IssueRow,
    Scan,
)
from core.secrets.openbao import OpenBaoClient, OpenBaoError

OPEN_STATES = ("new", "open", "reintroduced")
MIN_INTERVAL, MAX_INTERVAL = 15, 7 * 24 * 60
FAILURES_BEFORE_BACKOFF = 3


@dataclass(frozen=True)
class Kind:
    name: str
    label: str
    direction: str  # pull | push
    needs_credential: bool
    fields: tuple[str, ...]  # required config keys
    permissions: str  # what the credential (or App) needs, and nothing more


KINDS: dict[str, Kind] = {
    k.name: k
    for k in (
        Kind(
            "github_code_scanning",
            "GitHub code scanning",
            "pull",
            False,
            ("repo", "installation_id"),
            "The Bulwark GitHub App, installed on the repository, with Code scanning alerts: read.",
        ),
        Kind(
            "github_dependabot",
            "GitHub Dependabot",
            "pull",
            False,
            ("repo", "installation_id"),
            "The Bulwark GitHub App, installed on the repository, with Dependabot alerts: read.",
        ),
        Kind(
            "gitlab",
            "GitLab vulnerability report",
            "pull",
            True,
            ("base_url", "project"),
            "A token with the read_api scope, from a user with at least the Developer role "
            "(GitLab Ultimate).",
        ),
        Kind(
            "defectdojo_import",
            "DefectDojo (import from)",
            "pull",
            True,
            ("base_url", "product_id"),
            "An API v2 key for a DefectDojo user who can read the product.",
        ),
        Kind(
            "defectdojo_export",
            "DefectDojo (export to)",
            "push",
            True,
            ("base_url",),
            "An API v2 key for a DefectDojo user who can import scans into the engagement.",
        ),
    )
}


class ConnectorConfigError(ValueError):
    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- configuration --------------------------------------------------------------------------------


def validate_config(
    s: Session, org_id: str, kind: str, config: dict[str, Any], *, private_ok: bool | None = None
) -> dict[str, Any]:
    if kind not in KINDS:
        raise ConnectorConfigError("kind", f"kind must be one of {', '.join(KINDS)}")
    spec = KINDS[kind]
    c = {k: v for k, v in (config or {}).items() if v not in (None, "")}
    for name in spec.fields:
        if name not in c:
            raise ConnectorConfigError(name, f"{name} is required for {spec.label}")
    out: dict[str, Any] = {}
    if kind.startswith("github"):
        repo_name = str(c["repo"]).strip()
        if not github.REPO.match(repo_name):
            raise ConnectorConfigError("repo", "repo is owner/name, like acme/payments-api")
        inst = str(c["installation_id"]).strip()
        owned = s.scalars(
            select(GithubInstallation).where(
                GithubInstallation.id == inst, GithubInstallation.org_id == org_id
            )
        ).first()
        if owned is None:
            raise ConnectorConfigError(
                "installation_id",
                "that GitHub App installation does not belong to this organization",
            )
        out = {"repo": repo_name, "installation_id": inst}
        if c.get("api_url"):
            out["api_url"] = _url("api_url", str(c["api_url"]), private_ok)
    elif kind == "gitlab":
        project = str(c["project"]).strip().strip("/")
        if not re.match(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$", project):
            raise ConnectorConfigError(
                "project", "project is the full path, like group/subgroup/name"
            )
        out = {"base_url": _url("base_url", str(c["base_url"]), private_ok), "project": project}
    elif kind == "defectdojo_import":
        out = {
            "base_url": _url("base_url", str(c["base_url"]), private_ok),
            "product_id": _int("product_id", c["product_id"]),
        }
    else:
        out = {"base_url": _url("base_url", str(c["base_url"]), private_ok)}
        if c.get("engagement_id") is not None:
            out["engagement_id"] = _int("engagement_id", c["engagement_id"])
        elif c.get("product_name") and c.get("engagement_name"):
            out["product_name"] = str(c["product_name"])[:200]
            out["engagement_name"] = str(c["engagement_name"])[:200]
            out["product_type_name"] = str(c.get("product_type_name") or "Bulwark")[:200]
        else:
            raise ConnectorConfigError(
                "engagement_id", "give an engagement id, or a product and engagement name to create"
            )
        sources = c.get("exclude_sources", [defectdojo.SOURCE])
        out["exclude_sources"] = sorted({str(x) for x in sources} | {defectdojo.SOURCE})
    return out


def _url(name: str, value: str, private_ok: bool | None) -> str:
    try:
        return check_url(value, private_ok=private_ok)
    except ConnectorError as exc:
        raise ConnectorConfigError(name, str(exc)) from None


def _int(name: str, value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ConnectorConfigError(name, f"{name} is a number") from None
    if n < 1:
        raise ConnectorConfigError(name, f"{name} is a positive number")
    return n


def _openbao(settings: Settings) -> OpenBaoClient | None:
    if settings.openbao_addr and settings.openbao_token:
        return OpenBaoClient(addr=settings.openbao_addr, token=settings.openbao_token)
    return None


def _kv_path(c: Connector) -> str:
    return f"bulwark/connectors/{c.org_id}/{c.id}"


def set_credential(c: Connector, value: str | None, settings: Settings) -> None:
    """Into OpenBao's KV store when it is configured; otherwise into the row, and `credential_store`
    says which, so the API and the health screen can say a credential is not encrypted."""
    if not KINDS[c.kind].needs_credential:
        c.credential_store, c.credential = "none", None
        return
    if not value:
        raise ConnectorConfigError("credential", f"{KINDS[c.kind].label} needs a credential")
    client = _openbao(settings)
    if client is not None:
        client.ensure_kv_engine_enabled()
        client.put_secret(_kv_path(c), value)
        c.credential_store, c.credential = "openbao", None
    else:
        c.credential_store, c.credential = "database", value


def get_credential(c: Connector, settings: Settings) -> str:
    if c.credential_store == "database" and c.credential:
        return c.credential
    if c.credential_store == "openbao":
        client = _openbao(settings)
        if client is None:
            raise ConnectorError("the credential is in OpenBao, which is not configured now")
        try:
            value = client.get_secret(_kv_path(c))
        except OpenBaoError as exc:
            raise ConnectorError("could not read the credential from OpenBao") from exc
        if value:
            return value
    raise ConnectorError("the connector has no credential; add one", auth=True)


def create(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    kind: str,
    name: str,
    config: dict[str, Any],
    credential: str | None,
    settings: Settings,
    interval_minutes: int = 360,
    enabled: bool = True,
    close_on_empty: bool = False,
    created_by: str | None = None,
) -> Connector:
    clean = validate_config(s, org_id, kind, config)
    label = " ".join((name or KINDS[kind].label).split())[:200]
    c = Connector(
        org_id=org_id,
        asset_id=asset_id,
        kind=kind,
        name=label,
        config=clean,
        enabled=enabled,
        interval_minutes=_interval(interval_minutes),
        close_on_empty=close_on_empty,
        created_by=created_by,
        state={},
        status="never_run" if enabled else "disabled",
        next_run_at=_now(),
    )
    s.add(c)
    s.flush()
    set_credential(c, credential, settings)
    if KINDS[kind].direction == "pull":
        eng = repo.get_or_create_import_engagement(s, asset_id=asset_id, org_id=org_id)
        c.test_id = repo.get_or_create_engagement_test(
            s,
            org_id=org_id,
            engagement_id=eng.id,
            name=f"{label} (connector)",
            parser=f"connector:{kind}",
        ).id
    s.commit()
    return c


def _interval(minutes: int) -> int:
    return max(MIN_INTERVAL, min(MAX_INTERVAL, int(minutes)))


def get(s: Session, connector_id: str, org_id: str) -> Connector | None:
    return s.scalars(
        select(Connector).where(Connector.id == connector_id, Connector.org_id == org_id)
    ).one_or_none()


def list_for(s: Session, org_id: str, asset_id: str | None = None) -> list[Connector]:
    q = select(Connector).where(Connector.org_id == org_id)
    if asset_id:
        q = q.where(Connector.asset_id == asset_id)
    return list(s.scalars(q.order_by(Connector.name)))


def runs(s: Session, connector_id: str, org_id: str, limit: int = 20) -> list[ConnectorRun]:
    return list(
        s.scalars(
            select(ConnectorRun)
            .where(ConnectorRun.connector_id == connector_id, ConnectorRun.org_id == org_id)
            .order_by(ConnectorRun.started_at.desc())
            .limit(limit)
        )
    )


def due(s: Session, org_id: str, now: datetime | None = None) -> list[Connector]:
    now = now or _now()
    return [
        c
        for c in s.scalars(select(Connector).where(Connector.org_id == org_id, Connector.enabled))
        if c.next_run_at is None or _aware(c.next_run_at) <= now  # type: ignore[operator]
    ]


# --- health ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Health:
    status: str
    warning: str | None


def health(c: Connector) -> Health:
    if not c.enabled:
        return Health("disabled", None)
    if c.status == "failing":
        if c.consecutive_failures >= FAILURES_BEFORE_BACKOFF:
            return Health(
                "failing", f"Failed {c.consecutive_failures} times in a row: {c.last_error}"
            )
        return Health("failing", c.last_error)
    if c.status == "empty":
        if c.max_items_seen:
            return Health(
                "empty",
                (
                    f"Connected, but fetched nothing -- {c.max_items_seen} item(s) came back "
                    "before. "
                    "Nothing was closed. Check that the credential can still see the alerts; if "
                    "everything really was fixed, allow empty pulls to close them."
                ),
            )
        return Health(
            "empty",
            (
                "Connected, but fetched nothing. If you expected findings, check the "
                f"{_target_word(c)} and what the credential is allowed to see."
            ),
        )
    if c.credential_store == "database":
        return Health(
            c.status, "The credential is stored unencrypted: configure OpenBao to keep it there."
        )
    return Health(c.status, None)


def _target_word(c: Connector) -> str:
    return "repository" if c.kind.startswith("github") else "project or product"


# --- running --------------------------------------------------------------------------------------


@dataclass
class RunResult:
    run: ConnectorRun
    applied: bool
    warnings: list[str] = field(default_factory=list)


GithubToken = Callable[[str, Settings], str]


def _github_token(installation_id: str, settings: Settings) -> str:
    from core.github_app import GithubAppError, installation_token

    if not settings.github_app_id or not settings.github_app_private_key:
        raise ConnectorError("the GitHub App is not configured on this deployment")
    try:
        return installation_token(
            installation_id, settings.github_app_id, settings.github_app_private_key
        )
    except GithubAppError as exc:
        raise ConnectorError(f"GitHub refused an installation token: {exc}", auth=True) from exc


TRANSPORT: Transport = http_transport
GITHUB_TOKEN: GithubToken = _github_token


def _pull(
    c: Connector, settings: Settings, transport: Transport, github_token: GithubToken
) -> Fetched:
    cfg = c.config
    if c.kind == "github_code_scanning":
        token = github_token(cfg["installation_id"], settings)
        return github.fetch_code_scanning(
            transport, token, cfg["repo"], cfg.get("api_url", github.API)
        )
    if c.kind == "github_dependabot":
        token = github_token(cfg["installation_id"], settings)
        return github.fetch_dependabot(
            transport, token, cfg["repo"], cfg.get("api_url", github.API)
        )
    if c.kind == "gitlab":
        return gitlab.fetch(transport, cfg["base_url"], get_credential(c, settings), cfg["project"])
    if c.kind == "defectdojo_import":
        return defectdojo.fetch(
            transport, cfg["base_url"], get_credential(c, settings), cfg["product_id"]
        )
    raise ConnectorError(f"{c.kind} is not a pull connector")  # pragma: no cover


def open_issue_findings(
    s: Session, asset_id: str, exclude_sources: list[str]
) -> list[dict[str, Any]]:
    """Each open Issue of the project as its most recent occurrence (any scan or import)."""
    rows = s.execute(
        select(FindingRow.issue_id, FindingRow.data)
        .join(Scan, Scan.id == FindingRow.scan_id)
        .join(IssueRow, IssueRow.id == FindingRow.issue_id)
        .where(IssueRow.asset_id == asset_id, IssueRow.state.in_(OPEN_STATES))
        .order_by(Scan.created_at.desc())
    )
    seen: set[str] = set()
    out = []
    for issue_id, data in rows:
        if issue_id in seen:
            continue
        seen.add(issue_id)
        if (data.get("evidence", {}).get("reported_by") or [""])[0] in exclude_sources:
            continue
        out.append(data)
    return out


def run(
    s: Session,
    c: Connector,
    settings: Settings,
    *,
    transport: Transport | None = None,
    github_token: GithubToken | None = None,
    now: datetime | None = None,
) -> RunResult:
    """One pull or push, recorded whatever happens. Never raises for a connector failure: that is
    the connector's health, not the caller's problem."""
    # Looked up at call time, so a test (or a deployment) can replace the module-level defaults.
    transport = transport or TRANSPORT
    github_token = github_token or GITHUB_TOKEN
    started = now or _now()
    record = ConnectorRun(org_id=c.org_id, connector_id=c.id, started_at=started, outcome="failed")
    applied = False
    warnings: list[str] = []
    try:
        if KINDS[c.kind].direction == "push":
            exported = open_issue_findings(s, c.asset_id, c.config.get("exclude_sources", []))
            asset = repo.get_asset(s, c.asset_id, org_id=c.org_id)
            sarif = defectdojo.sarif_for(exported, asset.label if asset else c.asset_id)
            test = defectdojo.push(
                transport,
                c.config["base_url"],
                get_credential(c, settings),
                sarif,
                test_id=c.state.get("defectdojo_test_id"),
                engagement_id=c.config.get("engagement_id"),
                product_name=c.config.get("product_name"),
                engagement_name=c.config.get("engagement_name"),
                product_type_name=c.config.get("product_type_name", "Bulwark"),
            )
            c.state = {**c.state, "defectdojo_test_id": test}
            record.items, record.requests, record.outcome = len(exported), 1, "ok"
            record.counts = {"exported": len(exported), "defectdojo_test_id": test}
            applied = True
        else:
            fetched = _pull(c, settings, transport, github_token)
            warnings = list(fetched.warnings)
            record.items, record.requests = fetched.items, fetched.requests
            if fetched.items == 0 and c.max_items_seen > 0 and not c.close_on_empty:
                record.outcome = "empty"
                warnings.append("Fetched nothing after fetching items before; nothing was closed.")
            else:
                findings = prepare(fetched.findings)
                canonical = json.dumps(
                    sorted(json.dumps(f.to_dict(), sort_keys=True) for f in findings)
                )
                result = imports.apply_import(
                    s,
                    org_id=c.org_id,
                    test_id=_test(s, c),
                    findings=findings,
                    parser=f"connector:{c.kind}",
                    file_digest=hashlib.sha256(canonical.encode()).hexdigest(),
                    file_name=f"{c.name}: pull of {started:%Y-%m-%d %H:%M}",
                    close_missing=True,
                    created_by=f"connector:{c.id}",
                    warnings=warnings,
                )
                rec = result.record
                record.import_id = rec.id
                record.counts = {
                    "new": rec.new_count,
                    "unchanged": rec.unchanged_count,
                    "reopened": rec.reopened_count,
                    "closed": rec.closed_count,
                    "detached": rec.detached_count,
                    "held": rec.held_count,
                    "duplicate": not result.created,
                }
                record.outcome = "ok" if fetched.items else "empty"
                applied = True
            c.max_items_seen = max(c.max_items_seen, fetched.items)
        c.status = record.outcome
        c.last_success_at = started
        c.last_items = record.items
        c.last_error = None
        c.consecutive_failures = 0
    except (ConnectorError, imports.ImportRequestError) as exc:
        s.rollback()
        c = s.merge(c)
        record.outcome, record.error = "failed", str(exc)[:2000]
        c.status, c.last_error = "failing", record.error
        c.consecutive_failures += 1
    finished = _now() if now is None else started
    record.finished_at = finished
    record.warnings = warnings
    c.last_run_at = started
    backoff = 2 ** min(max(c.consecutive_failures - 1, 0), 4) if c.consecutive_failures else 1
    c.next_run_at = started + timedelta(minutes=c.interval_minutes * backoff)
    s.add(record)
    repo.add_outbox_event(
        s,
        org_id=c.org_id,
        event_type="connector.run",
        payload={
            "connector_id": c.id,
            "kind": c.kind,
            "outcome": record.outcome,
            "items": record.items,
            "error": record.error,
        },
    )
    s.commit()
    return RunResult(record, applied, warnings)


def _test(s: Session, c: Connector) -> str:
    """The connector's Test, recreated if someone deleted it."""
    if c.test_id and repo.get_engagement_test(s, c.test_id, c.org_id) is not None:
        return c.test_id
    eng = repo.get_or_create_import_engagement(s, asset_id=c.asset_id, org_id=c.org_id)
    c.test_id = repo.get_or_create_engagement_test(
        s,
        org_id=c.org_id,
        engagement_id=eng.id,
        name=f"{c.name} (connector)",
        parser=f"connector:{c.kind}",
    ).id
    return c.test_id


__all__ = [
    "KINDS",
    "ConnectorConfigError",
    "Health",
    "RunResult",
    "create",
    "due",
    "get",
    "get_credential",
    "health",
    "list_for",
    "run",
    "runs",
    "set_credential",
    "validate_config",
]
