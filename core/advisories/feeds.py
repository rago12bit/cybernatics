"""Fetching advisories on a schedule (plan §46.2): OSV's per-ecosystem data (which carries GitHub's
advisories, the PyPI and Go databases and malicious-package reports), CISA's KEV catalog, and
recently changed CVEs from NVD's public API (no key).

OSV: the first run reads the ecosystem's `all.zip`; later runs read `modified_id.csv` (newest
first) only down to the last change already seen, and fetch just those records -- falling back to
the zip when too many changed. Every fetch is HTTPS to a fixed host, size-limited, and a failure is
recorded on the feed's state rather than raised, so one source being down never stops the others.
NVD without a key allows 5 requests in 30 seconds; requests are spaced accordingly.
"""

from __future__ import annotations

import json
import logging
import ssl
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import IO

from sqlalchemy.orm import Session

from core.advisories import store
from core.advisories.osv import ECOSYSTEMS, Advisory, parse, parse_time

log = logging.getLogger(__name__)

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ALLOWED_HOSTS = frozenset(
    {"osv-vulnerabilities.storage.googleapis.com", "www.cisa.gov", "services.nvd.nist.gov"}
)
MAX_ZIP_BYTES = 1024 * 1024 * 1024  # npm's all.zip is ~220 MB today
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_INCREMENTAL = 3000  # more changed records than this: read the zip instead
NVD_PAGE = 2000
NVD_SPACING_SECONDS = 6.5  # 5 requests per 30 seconds without a key

Opener = Callable[[str], IO[bytes]]


def _tls() -> ssl.SSLContext:
    """Certificates verified against Mozilla's CA bundle (certifi, already installed with httpx),
    so a Python without system CAs configured still verifies rather than fails or skips it."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover - certifi comes with httpx
        return ssl.create_default_context()


def _open(url: str, timeout: float = 120.0) -> IO[bytes]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"advisory feeds are fetched from known HTTPS hosts only, not {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": "bulwark-advisories"})
    return urllib.request.urlopen(req, timeout=timeout, context=_tls())  # type: ignore[no-any-return]  # noqa: S310


def _read(opener: Opener, url: str, limit: int) -> bytes:
    with opener(url) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{url} is larger than {limit} bytes")
    return data


@dataclass
class OsvRun:
    ecosystem: str
    mode: str = ""  # full | incremental | unchanged
    seen: int = 0
    changed: set[str] = field(default_factory=set)
    vuln_keys: set[str] = field(default_factory=set)
    cursor: str = ""


def _records_from_zip(fh: IO[bytes]) -> Iterator[Advisory]:
    with zipfile.ZipFile(fh) as z:
        for info in z.infolist():
            if info.file_size > MAX_RECORD_BYTES or not info.filename.endswith(".json"):
                continue
            a = parse(z.read(info))
            if a is not None:
                yield a


def _old_key_map(s: Session, ids: set[str]) -> dict[str, str]:
    """Each known advisory's current vuln_key: if an update changes a record's aliases, the
    impacts filed under its old key must be re-matched too."""
    from sqlalchemy import select

    from core.persistence.models import Advisory as Row

    out: dict[str, str] = {}
    seq = sorted(ids)
    for i in range(0, len(seq), 500):
        q = select(Row.id, Row.vuln_key).where(Row.id.in_(seq[i : i + 500]))
        out.update((aid, key) for aid, key in s.execute(q))
    return out


def _stamp(text: str) -> datetime | None:
    return parse_time(text)


def update_osv(
    s: Session,
    osv_ecosystem: str,
    *,
    opener: Opener = _open,
    zip_path: Path | None = None,
) -> OsvRun:
    """Bring one ecosystem up to date. `zip_path` reads a downloaded `all.zip` instead of fetching
    one (an air-gapped install, or a test); the cursor is then the newest record in it."""
    if osv_ecosystem not in ECOSYSTEMS:
        raise ValueError(f"unsupported OSV ecosystem {osv_ecosystem!r}")
    source = f"osv:{osv_ecosystem}"
    state = store.feed(s, source)
    since = _stamp(state.cursor) if state.cursor else None
    run = OsvRun(osv_ecosystem)
    newest = ""
    pending: list[str] = []
    overflow = False
    if zip_path is None:
        # Newest first: read down to the last change already seen. On a first run only the top
        # line is needed -- it becomes the cursor, read *before* the dump, so nothing changed
        # in between is ever skipped (re-reading a record is harmless).
        with opener(f"{OSV_BASE}/{osv_ecosystem}/modified_id.csv") as resp:
            for raw in resp:
                stamp, _, aid = raw.decode("utf-8", "replace").strip().partition(",")
                when = _stamp(stamp)
                if not aid or when is None:
                    continue
                newest = newest or stamp
                if since is None:
                    break
                if when <= since:  # already read: the cursor was taken before the last dump
                    break
                pending.append(aid)
                if len(pending) > MAX_INCREMENTAL:
                    overflow = True
                    break
        if since is not None and not pending:
            run.mode, run.cursor = "unchanged", state.cursor
            store.record_run(s, source, ok=True, records=state.records, cursor=state.cursor)
            return run
    if since is not None and pending and not overflow and zip_path is None:
        run.mode = "incremental"
        records = []
        for aid in pending:
            if not aid.replace("-", "").replace("_", "").replace(".", "").isalnum():
                continue
            a = parse(_read(opener, f"{OSV_BASE}/{osv_ecosystem}/{aid}.json", MAX_RECORD_BYTES))
            if a is not None:
                records.append(a)
    else:
        run.mode = "full"
        if zip_path is not None:
            with zip_path.open("rb") as fh:
                records = list(_records_from_zip(fh))
            newest = max((a.modified for a in records), default=_now()).isoformat()
        else:
            url = f"{OSV_BASE}/{osv_ecosystem}/all.zip"
            with tempfile.TemporaryFile() as tmp, opener(url) as resp:
                copied = 0
                while chunk := resp.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > MAX_ZIP_BYTES:
                        raise ValueError("OSV dump larger than the limit")
                    tmp.write(chunk)
                tmp.seek(0)
                records = list(_records_from_zip(tmp))
    old = _old_key_map(s, {a.id for a in records})
    result = store.upsert(s, records, source=osv_ecosystem)
    run.seen, run.changed = result.seen, result.changed
    run.vuln_keys = result.vuln_keys | {old[i] for i in result.changed if i in old}
    run.cursor = newest or state.cursor
    store.record_run(s, source, ok=True, records=result.seen, cursor=run.cursor)
    return run


def _now() -> datetime:
    return datetime.now(timezone.utc)


def update_kev(s: Session, *, opener: Opener = _open) -> int:
    n = store.load_kev(s, _read(opener, KEV_URL, 20 * 1024 * 1024))
    store.record_run(s, "kev", ok=True, records=n)
    return n


def update_nvd(
    s: Session,
    *,
    opener: Opener = _open,
    days: int = 2,
    max_pages: int = 10,
    sleep: Callable[[float], None] = time.sleep,
    now: datetime | None = None,
) -> int:
    """CVEs NVD changed in the last `days` days (at most 120, the API's window)."""
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(days=min(days, 120))
    fmt = "%Y-%m-%dT%H:%M:%S.000+00:00"
    total, index = 0, 0
    for page in range(max_pages):
        if page:
            sleep(NVD_SPACING_SECONDS)
        q = urllib.parse.urlencode({
            "lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt),
            "resultsPerPage": NVD_PAGE, "startIndex": index,
        })  # fmt: skip
        doc = json.loads(_read(opener, f"{NVD_URL}?{q}", 64 * 1024 * 1024))
        items = doc.get("vulnerabilities") or []
        total += store.upsert_cves(s, items)
        index += len(items)
        if not items or index >= int(doc.get("totalResults") or 0):
            break
    store.record_run(s, "nvd", ok=True, records=total, cursor=end.isoformat())
    return total


@dataclass
class UpdateResult:
    vuln_keys: set[str] = field(default_factory=set)
    errors: dict[str, str] = field(default_factory=dict)
    runs: list[OsvRun] = field(default_factory=list)


def update_all(s: Session, *, opener: Opener = _open, nvd: bool = True) -> UpdateResult:
    """Every source; a failing one is recorded and skipped."""
    out = UpdateResult()
    for eco in ECOSYSTEMS:
        try:
            run = update_osv(s, eco, opener=opener)
            out.runs.append(run)
            out.vuln_keys |= run.vuln_keys
        except Exception as exc:  # noqa: BLE001 - one source down must not stop the others
            s.rollback()
            out.errors[f"osv:{eco}"] = f"{type(exc).__name__}: {exc}"
            store.record_run(s, f"osv:{eco}", ok=False, error=out.errors[f"osv:{eco}"])
    for name, fn in (("kev", update_kev), ("nvd", update_nvd if nvd else None)):
        if fn is None:
            continue
        try:
            fn(s, opener=opener)
        except Exception as exc:  # noqa: BLE001
            s.rollback()
            out.errors[name] = f"{type(exc).__name__}: {exc}"
            store.record_run(s, name, ok=False, error=out.errors[name])
    return out
