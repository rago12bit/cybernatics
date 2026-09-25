"""EPSS and CISA KEV feeds: download, validate, cache, look up.

Both are public files. They are fetched by the API/worker side only (scanner containers never get
a network) into `<workdir>/feeds`, validated before they replace the cached copy, and read back
per scan. A missing or corrupt cache is not an error: scoring degrades to "no exploit data".
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import re
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import Settings

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"  # FIRST.org EPSS daily scores
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 64 * 1024 * 1024  # both feeds are well under 10 MB; this only bounds a hostile response
MIN_EPSS_ROWS, MIN_KEV_ENTRIES = (
    1000,
    100,
)  # sanity floors: a truncated download must not replace a good cache
STALE_AFTER_HOURS = 48

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
Fetcher = Callable[[str], bytes]


def feeds_dir() -> Path:
    d = Settings.from_env().workdir / "feeds"
    d.mkdir(parents=True, exist_ok=True)
    return d


def http_get(url: str, timeout: float = 30.0) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("feeds are fetched over https only")
    req = urllib.request.Request(url, headers={"User-Agent": "bulwark-feed-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        data: bytes = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"feed larger than {MAX_BYTES} bytes")
    return data


def _parse_epss(raw: bytes) -> tuple[dict[str, float], str]:
    text = gzip.decompress(raw).decode("utf-8", "replace")
    date = ""
    m = re.match(r"#.*?score_date:([0-9T:\-\.Z]+)", text)
    if m:
        date = m.group(1)
    rows = csv.reader(
        io.StringIO("\n".join(ln for ln in text.splitlines() if not ln.startswith("#")))
    )
    header = next(rows, [])
    if header[:2] != ["cve", "epss"]:
        raise ValueError("unexpected EPSS header")
    out: dict[str, float] = {}
    for r in rows:
        if len(r) >= 2 and _CVE.match(r[0]):
            try:
                v = float(r[1])
            except ValueError:
                continue
            if 0.0 <= v <= 1.0:
                out[r[0]] = v
    return out, date


def _parse_kev(raw: bytes) -> tuple[set[str], dict[str, Any]]:
    doc = json.loads(raw)
    vulns = doc["vulnerabilities"]
    ids = {v["cveID"] for v in vulns if isinstance(v, dict) and _CVE.match(str(v.get("cveID", "")))}
    return ids, {"version": doc.get("catalogVersion", ""), "released": doc.get("dateReleased", "")}


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def update_feeds(directory: Path | None = None, fetch: Fetcher = http_get) -> dict[str, Any]:
    """Download both feeds. Each is validated first; a bad one leaves the previous cache intact."""
    d = directory or feeds_dir()
    meta = read_meta(d)
    errors: dict[str, str] = {}
    try:
        raw = fetch(EPSS_URL)
        scores, date = _parse_epss(raw)
        if len(scores) < MIN_EPSS_ROWS:
            raise ValueError(f"only {len(scores)} EPSS rows")
        _atomic_write(d / "epss.csv.gz", raw)
        meta["epss"] = {"date": date, "rows": len(scores)}
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        errors["epss"] = f"{type(exc).__name__}: {exc}"
    try:
        raw = fetch(KEV_URL)
        ids, info = _parse_kev(raw)
        if len(ids) < MIN_KEV_ENTRIES:
            raise ValueError(f"only {len(ids)} KEV entries")
        _atomic_write(d / "kev.json", raw)
        meta["kev"] = {**info, "entries": len(ids)}
    except Exception as exc:  # noqa: BLE001
        errors["kev"] = f"{type(exc).__name__}: {exc}"
    if "epss" not in errors or "kev" not in errors:
        meta["fetched_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta["errors"] = errors
    _atomic_write(d / "meta.json", json.dumps(meta, indent=1).encode())
    return meta


def read_meta(directory: Path | None = None) -> dict[str, Any]:
    try:
        meta: dict[str, Any] = json.loads(((directory or feeds_dir()) / "meta.json").read_text())
        return meta
    except (OSError, ValueError):
        return {}


def is_stale(meta: dict[str, Any], now: datetime | None = None) -> bool:
    try:
        at = datetime.fromisoformat(meta["fetched_at"])
    except (KeyError, ValueError):
        return True
    return ((now or datetime.now(timezone.utc)) - at).total_seconds() > STALE_AFTER_HOURS * 3600


@dataclass
class Feeds:
    epss: dict[str, float] = field(default_factory=dict)
    kev: set[str] = field(default_factory=set)
    epss_loaded: bool = False
    kev_loaded: bool = False

    @classmethod
    def load(cls, wanted: set[str], directory: Path | None = None) -> Feeds:
        """Read only the CVEs we need (the EPSS file has ~300k rows; a scan touches a handful)."""
        d = directory or feeds_dir()
        f = cls()
        try:
            text = gzip.decompress((d / "epss.csv.gz").read_bytes()).decode("utf-8", "replace")
            for line in text.splitlines():
                head, _, rest = line.partition(",")
                if head in wanted and _CVE.match(head):
                    try:
                        v = float(rest.split(",")[0])
                    except ValueError:
                        continue
                    if 0.0 <= v <= 1.0:  # the cache is validated on download; check again on read
                        f.epss[head] = v
            f.epss_loaded = True
        except (OSError, ValueError, EOFError):
            pass
        try:
            f.kev = _parse_kev((d / "kev.json").read_bytes())[0] & wanted
            f.kev_loaded = True
        except (OSError, ValueError, KeyError):
            pass
        return f


def ensure_fresh(fetch: Fetcher = http_get) -> None:
    """Refresh the cache if missing or old. Best effort: a scan never fails because a feed did."""
    if os.environ.get("BULWARK_OFFLINE") == "1":
        return
    try:
        if is_stale(read_meta()):
            update_feeds(fetch=fetch)
    except Exception:  # noqa: BLE001
        pass
