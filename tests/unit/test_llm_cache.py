from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from core.llm import cache as cache_mod
from core.llm.cache import PATCH_MOVED, cache_key, lookup, rule_id, stats, suggest_cached
from core.llm.limits import LimitExceeded, UsageLimiter
from core.llm.prompt import CodeContext
from core.models import Category, Finding, Location, Package, Taxonomy
from core.persistence.models import Base
from core.rag.store import KnowledgeBase, load_corpus
from tests.unit.test_llm import CHUNKS, GOOD, PATH, FakeModel, reply

SNIPPET = "def get(uid):\n    return db.execute('SELECT * FROM t WHERE id=' + uid)"
CODE = CodeContext(SNIPPET, 10)


def mk(
    path: str = PATH,
    line: int = 10,
    snippet: str = SNIPPET,
    rule: str = "B608",
    cat: Category = Category.SAST,
) -> Finding:
    f = Finding(
        id=f"{path}:{line}", title="SQL injection", description="String-built SQL.",
        location=Location(path, line, line + 1, snippet, Location.hash_snippet(snippet) if snippet else ""),
        taxonomy=Taxonomy(cat, cwe=("CWE-89",), owasp_top_10_2021=("A03:2021",)),
    )  # fmt: skip
    f.evidence.rule_ids = {"bandit": [rule]}
    return f


def patch_for(path: str, line: int = 10) -> str:
    return (f"--- a/{path}\n+++ b/{path}\n@@ -{line},2 +{line},2 @@\n def get(uid):\n"
            "-    return db.execute('SELECT * FROM t WHERE id=' + uid)\n"
            "+    return db.execute('SELECT * FROM t WHERE id=?', (uid,))\n")  # fmt: skip


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        load_corpus(s, CHUNKS)
        yield s


@pytest.fixture
def kb(db: Session) -> KnowledgeBase:
    return KnowledgeBase(db)


# ---- keys -------------------------------------------------------------------------------------------


def test_key_is_stable_and_sensitive_to_rule_snippet_model_and_prompt_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = cache_key(mk(), "m1")
    assert base and base == cache_key(
        mk(path="other/file.py", line=99), "m1"
    )  # location is not part of the key
    assert base != cache_key(mk(rule="B609"), "m1")
    assert base != cache_key(mk(snippet=SNIPPET + " # changed"), "m1")
    assert base != cache_key(mk(), "m2")
    monkeypatch.setattr(cache_mod, "PROMPT_VERSION", "different")
    assert base != cache_key(mk(), "m1")


def test_dependency_findings_are_keyed_by_cve_and_package_version() -> None:
    def dep(version: str, cve: str = "CVE-2021-23337") -> Finding:
        f = Finding(
            "d",
            "lodash",
            "d",
            Location("package-lock.json", 1, 1),
            Taxonomy(Category.SCA, cve=(cve,)),
        )
        f.package = Package("lodash", version, "npm")
        return f

    assert rule_id(dep("4.17.4")) == "CVE-2021-23337"
    assert cache_key(dep("4.17.4"), "m") == cache_key(dep("4.17.4"), "m")
    assert cache_key(dep("4.17.4"), "m") != cache_key(dep("4.17.21"), "m")
    assert cache_key(dep("4.17.4"), "m") != cache_key(dep("4.17.4", "CVE-2020-8203"), "m")


def test_findings_that_cannot_be_keyed_safely_are_never_cached() -> None:
    assert cache_key(mk(snippet=""), "m") is None
    assert cache_key(mk(snippet="[snippet withheld: near a detected secret]"), "m") is None
    assert cache_key(mk(snippet="[secret redacted]"), "m") is None
    secret = mk(snippet="[secret redacted]", cat=Category.SECRETS)
    assert (
        cache_key(secret, "m") is not None
    )  # secrets send no code, so the answer does not depend on it


# ---- behaviour --------------------------------------------------------------------------------------


def test_the_same_rule_and_snippet_in_another_scan_costs_one_model_call(
    db: Session, kb: KnowledgeBase
) -> None:
    model = FakeModel(reply(suggested_patch=patch_for("a/one.py")))
    first = suggest_cached(mk("a/one.py"), kb, model, db, CODE)
    second = suggest_cached(mk("b/two.py", line=55), kb, model, db, CODE)
    third = suggest_cached(mk("c/three.py", line=7), kb, model, db, CODE)
    assert len(model.calls) == 1
    assert [r.from_cache for r in (first, second, third)] == [False, True, True]
    assert (
        second.explanation == first.explanation
        and second.source == "ai"
        and second.generated_at == first.generated_at
    )
    assert stats(db) == {"entries": 1, "hits": 2}


def test_a_cached_patch_is_dropped_when_it_belongs_to_a_different_place(
    db: Session, kb: KnowledgeBase
) -> None:
    model = FakeModel(reply(suggested_patch=patch_for("a/one.py")))
    first = suggest_cached(mk("a/one.py"), kb, model, db, CODE)
    assert first.suggested_patch and "a/one.py" in first.suggested_patch
    elsewhere = suggest_cached(mk("b/two.py"), kb, model, db, CODE)
    assert elsewhere.suggested_patch is None and PATCH_MOVED in elsewhere.warnings
    again = suggest_cached(
        mk("a/one.py"), kb, model, db, CODE
    )  # same file and line: the patch is valid
    assert again.suggested_patch == first.suggested_patch and PATCH_MOVED not in again.warnings


def test_switching_model_or_prompt_never_serves_stale_text(
    db: Session, kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    a, b = FakeModel(reply()), FakeModel(reply(explanation="Different model, different words."))
    b.model = "fake-model-2"
    suggest_cached(mk(), kb, a, db, CODE)
    assert suggest_cached(mk(), kb, b, db, CODE).explanation.startswith("Different model")
    monkeypatch.setattr(cache_mod, "PROMPT_VERSION", "v2")
    suggest_cached(mk(), kb, a, db, CODE)
    assert len(a.calls) == 2  # the edited prompt invalidated the first entry


def test_failures_and_static_fallbacks_are_never_cached(db: Session, kb: KnowledgeBase) -> None:
    bad = FakeModel('{"explanation": "x"}')  # breaks the contract
    assert suggest_cached(mk(), kb, bad, db, CODE).source == "static"
    assert suggest_cached(mk(), kb, bad, db, CODE).source == "static"
    assert (
        len(bad.calls) == 4 and stats(db)["entries"] == 0
    )  # retried each time (incl. 1 repair), not remembered
    boom = FakeModel(RuntimeError("down"))
    suggest_cached(mk(), kb, boom, db, CODE)
    assert stats(db)["entries"] == 0
    good = FakeModel(reply())
    assert suggest_cached(mk(), kb, good, db, CODE).from_cache is False  # a later success is stored
    assert stats(db)["entries"] == 1


def test_a_finding_that_cannot_be_keyed_still_gets_a_suggestion_but_is_not_stored(
    db: Session, kb: KnowledgeBase
) -> None:
    m = FakeModel(reply(suggested_patch=None))
    r1 = suggest_cached(mk(snippet=""), kb, m, db, None)
    r2 = suggest_cached(mk(snippet=""), kb, m, db, None)
    assert r1.source == r2.source == "ai" and len(m.calls) == 2 and stats(db)["entries"] == 0


def test_lookup_returns_nothing_for_a_miss_and_counts_hits(db: Session, kb: KnowledgeBase) -> None:
    assert lookup(db, mk(), "fake-model-1") is None
    suggest_cached(mk(), kb, FakeModel(reply()), db, CODE)
    got = lookup(db, mk(), "fake-model-1")
    assert got and got.from_cache and stats(db)["hits"] == 1


def test_the_limiter_hook_runs_only_on_a_miss_and_a_refusal_stores_nothing(
    db: Session, kb: KnowledgeBase
) -> None:
    calls: list[int] = []
    m = FakeModel(reply())
    suggest_cached(mk(), kb, m, db, CODE, before_call=lambda: calls.append(1))
    suggest_cached(mk(), kb, m, db, CODE, before_call=lambda: calls.append(1))  # cache hit: free
    assert calls == [1]

    def deny() -> None:
        raise LimitExceeded(30, "per minute")

    with pytest.raises(LimitExceeded):
        suggest_cached(mk(rule="B999"), kb, m, db, CODE, before_call=deny)
    assert len(m.calls) == 1 and stats(db)["entries"] == 1


def test_concurrent_requests_for_the_same_finding_share_one_model_call(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'c.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as s:
        load_corpus(s, CHUNKS)
    gate = threading.Barrier(8)
    model = FakeModel(reply(suggested_patch=None))
    slow = model.complete

    def slow_complete(system: str, user: str) -> str:
        threading.Event().wait(0.15)  # long enough for the others to queue up behind the lock
        return slow(system, user)

    model.complete = slow_complete  # type: ignore[method-assign]
    results: list[Any] = []

    def worker() -> None:
        with factory() as s:
            gate.wait()
            results.append(suggest_cached(mk(), KnowledgeBase(s), model, s, CODE))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(results) == 8 and len(model.calls) == 1
    assert sum(1 for r in results if not r.from_cache) == 1 and all(
        r.source == "ai" for r in results
    )


# ---- the limiter --------------------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_limiter_enforces_per_minute_and_per_day_with_a_sliding_window() -> None:
    clock = Clock()
    lim = UsageLimiter(per_minute=2, per_day=3, clock=clock)
    lim.acquire()
    lim.acquire()
    with pytest.raises(LimitExceeded) as e:
        lim.acquire()
    assert e.value.window == "per minute" and 1 <= e.value.retry_after <= 60
    clock.t += 61
    lim.acquire()  # the minute window slid; that is call 3 of 3 today
    clock.t += 61
    with pytest.raises(LimitExceeded) as d:
        lim.acquire()
    assert d.value.window == "per day" and d.value.retry_after > 60
    clock.t += 86_400
    lim.acquire()  # a day later everything is forgotten


def test_limiter_reads_its_limits_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BULWARK_LLM_MAX_PER_MINUTE", "1")
    monkeypatch.setenv("BULWARK_LLM_MAX_PER_DAY", "5")
    lim = UsageLimiter.from_env()
    lim.acquire()
    with pytest.raises(LimitExceeded):
        lim.acquire()


def test_cached_payload_holds_no_request_specific_data(db: Session, kb: KnowledgeBase) -> None:
    suggest_cached(
        mk(), kb, FakeModel(reply()), db, CodeContext("k = 'AKIAIOSFODNN7EXAMPLE'\n" + SNIPPET, 9)
    )
    from core.persistence.models import RemediationCache

    row = db.query(RemediationCache).one()
    blob = json.dumps(row.payload)
    assert "warnings" not in row.payload and "AKIA" not in blob and row.payload["source"] == "ai"
    assert row.payload["explanation"] == GOOD["explanation"]
