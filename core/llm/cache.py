"""Response cache for AI suggestions, keyed on (rule, snippet hash) as the design doc asks.

What makes two findings "the same": the rule that fired plus the code it fired on (`snippet_hash`). For
dependency findings there is no code, so the package and version stand in for it. Also part of the key: the
model and the prompt version, so switching model or editing the prompt never serves stale text.

Deliberately NOT cached: static fallbacks and failures (they are cheap or transient), findings whose snippet
was withheld or is missing (a shared key would merge unrelated code), and anything else we cannot key safely.

A cached patch belongs to the file and line it was written for. When the same rule and snippet turn up
somewhere else, the explanation and fix summary are reused (that is the saving) but the patch is dropped,
because its file header and line numbers would not match.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.llm.client import LLMClient
from core.llm.prompt import PROMPT_VERSION, CodeContext
from core.llm.service import RemediationResult, suggest
from core.models import Category, Finding
from core.persistence.models import RemediationCache
from core.rag.store import KnowledgeBase
from core.redact import WITHHELD

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()
PATCH_MOVED = "The cached patch was written for a different file or line, so it is not shown; the explanation applies."


def rule_id(f: Finding) -> str:
    """The CVE for a dependency finding, else the first scanner rule that fired."""
    if f.taxonomy.category is Category.SCA and f.taxonomy.cve:
        return f.taxonomy.cve[0]
    for tool, rules in f.evidence.rule_ids.items():
        if rules:
            return f"{tool}/{rules[0]}"
    return f"bulwark/{f.taxonomy.category.value}"


def cache_key(f: Finding, model: str) -> str | None:
    """None means "do not cache this one"."""
    rid = rule_id(f)
    if f.package is not None:
        anchor = f"pkg:{f.package.ecosystem}/{f.package.name}@{f.package.version}"
    elif f.taxonomy.category is Category.SECRETS:
        anchor = "secret"  # no code is sent for secrets, so the answer does not depend on it
    else:
        snippet = f.location.snippet
        if (
            not snippet.strip()
            or WITHHELD in snippet
            or "[snippet withheld" in snippet
            or "[secret redacted]" in snippet
        ):
            return None
        anchor = f.location.snippet_hash or "sha256:" + hashlib.sha256(snippet.encode()).hexdigest()
    return hashlib.sha256(f"{rid}\x1f{anchor}\x1f{model}\x1f{PROMPT_VERSION}".encode()).hexdigest()


def _store(s: Session, key: str, f: Finding, res: RemediationResult) -> None:
    payload = asdict(res)
    for k in ("warnings", "degraded_reason", "from_cache"):
        payload.pop(k, None)  # request-specific, not part of the reusable answer
    payload["generated_at"] = res.generated_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    row = s.get(RemediationCache, key)
    if row is None:
        s.add(RemediationCache(key=key, rule_id=rule_id(f)[:300], model=res.model or "", prompt_version=PROMPT_VERSION,
                               path=f.location.path, start_line=f.location.start_line, payload=payload, hits=0))  # fmt: skip
    s.commit()


def lookup(s: Session, f: Finding, model: str) -> RemediationResult | None:
    key = cache_key(f, model)
    row = s.get(RemediationCache, key) if key else None
    if row is None:
        return None
    row.hits += 1
    s.commit()
    p = dict(row.payload)
    warnings: list[str] = []
    if (row.path, row.start_line) != (f.location.path, f.location.start_line) and p.get(
        "suggested_patch"
    ):
        p["suggested_patch"] = None
        warnings.append(PATCH_MOVED)
    return RemediationResult(**{**p, "warnings": warnings, "from_cache": True})


def suggest_cached(
    f: Finding,
    kb: KnowledgeBase,
    client: LLMClient,
    s: Session,
    code: CodeContext | None,
    before_call: Callable[[], None] | None = None,
) -> RemediationResult:
    """Cache hit -> free. Miss -> (before_call, e.g. the spend limiter) -> one model call -> store if it worked.

    Concurrent requests for the same key share one model call (single flight): the others wait, then read the cache.
    """
    key = cache_key(f, client.model)
    if key is None:
        if before_call:
            before_call()
        return suggest(f, kb, client, code)
    with _locks_guard:
        lock = _locks.setdefault(key, threading.Lock())
    with lock:
        s.expire_all()  # another thread may have stored the answer while we waited
        if hit := lookup(s, f, client.model):
            return hit
        if before_call:
            before_call()
        res = suggest(f, kb, client, code)
        if res.source == "ai":
            res.generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _store(s, key, f, res)
        return res


def stats(s: Session) -> dict[str, int]:
    n = s.scalar(select(func.count()).select_from(RemediationCache)) or 0
    hits = s.scalar(select(func.coalesce(func.sum(RemediationCache.hits), 0))) or 0
    return {"entries": int(n), "hits": int(hits)}
