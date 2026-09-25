"""Evaluation of AI remediation quality (Week 14): sampling, running, hand-scoring, reporting.

Protocol and rubric: docs/evaluation-remediation.md. This module holds the parts that can be tested without
a model or a person: how the sample is drawn, the scoring schema, and how scores become published numbers.

Nothing here invents a result. `report()` refuses to run on unscored data, and every number it emits carries
its sample size and a 95% Wilson interval, because with ~50 items the intervals are wide and must be shown.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import Any

from core.llm.client import LLMClient
from core.llm.prompt import PROMPT_VERSION, CodeContext
from core.llm.service import suggest
from core.models import finding_from_dict
from core.rag.store import KnowledgeBase

CODE_CATEGORIES = {"sast", "iac", "container"}
DEFAULT_N = 50
DEFAULT_CODE_SHARE = (
    0.7  # patches are only possible for code findings; dependency findings get fix guidance
)

# Hand-scoring schema. `None` means "not applicable / not scored".
SCALES: dict[str, tuple[int, ...]] = {
    "explanation_accurate": (0, 1, 2),  # 0 wrong or misleading, 1 partly right, 2 accurate
    "fix_correct": (0, 1, 2),  # 0 wrong or harmful, 1 generic or incomplete, 2 correct and specific
    "patch_correct": (0, 1, 2),  # only when a patch is shown
    "unsafe": (0, 1),  # 1 = the suggestion would introduce a new vulnerability or a bad practice
    "hallucination": (0, 1),  # 1 = refers to code, APIs or files that are not in the snippet
    "static_fix_correct": (
        0,
        1,
        2,
    ),  # optional: the same rubric applied to the reference guidance (baseline)
}
REQUIRED = ("explanation_accurate", "fix_correct", "unsafe", "hallucination")


def has_code(f: dict[str, Any]) -> bool:
    sn = f["location"]["snippet"]
    return bool(sn.strip()) and "[snippet withheld" not in sn and "[secret redacted]" not in sn


def rule_key(f: dict[str, Any]) -> str:
    tax = f["taxonomy"]
    if tax["category"] == "sca" and tax["cve"]:
        return str(tax["cve"][0])
    for tool, rules in f["evidence"]["rule_ids"].items():
        if rules:
            return f"{tool}/{rules[0]}"
    return f"other/{tax['category']}"


def item_id(repo: str, finding_id: str) -> str:
    return hashlib.sha1(f"{repo}\x00{finding_id}".encode()).hexdigest()[:10]


def _round_robin(
    groups: dict[str, list[dict[str, Any]]], quota: int, rng: random.Random
) -> list[dict[str, Any]]:
    """One finding per group in random group order, then a second per group, and so on, until `quota`."""
    keys = sorted(groups)
    rng.shuffle(keys)
    for k in keys:
        rng.shuffle(groups[k])
    picked: list[dict[str, Any]] = []
    depth = 0
    while len(picked) < quota and any(len(v) > depth for v in groups.values()):
        for k in keys:
            if len(picked) >= quota:
                break
            if len(groups[k]) > depth:
                picked.append(groups[k][depth])
        depth += 1
    return picked


def select_sample(
    findings: list[dict[str, Any]],
    n: int = DEFAULT_N,
    seed: int = 1,
    code_share: float = DEFAULT_CODE_SHARE,
) -> list[dict[str, Any]]:
    """A deterministic sample spread over rules, not over findings.

    Random sampling would hand us dozens of copies of one noisy rule (one Semgrep rule made 111 of NodeGoat's
    findings). Instead: group by rule (the CVE, for dependencies), take one finding per group in random order,
    then a second per group, and so on. Code findings fill `code_share` of the sample (they are the ones that
    can carry a patch); dependency findings fill the rest. Secrets are excluded: no code is sent for them.
    Each finding must carry `_repo`.
    """
    rng = random.Random(seed)
    code: dict[str, list[dict[str, Any]]] = defaultdict(list)
    deps: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        cat = f["taxonomy"]["category"]
        if cat in CODE_CATEGORIES and has_code(f):
            code[rule_key(f)].append(f)
        elif cat == "sca":
            deps[rule_key(f)].append(f)
    n_code = min(round(n * code_share), sum(len(v) for v in code.values()))
    chosen = _round_robin(code, n_code, rng)
    chosen += _round_robin(deps, n - len(chosen), rng)
    if len(chosen) < n:  # not enough dependency findings: top up with more code findings
        rest = {k: [f for f in v if f not in chosen] for k, v in code.items()}
        chosen += _round_robin(rest, n - len(chosen), rng)
    out = []
    for f in chosen:
        out.append(
            {
                "item_id": item_id(f["_repo"], f["id"]),
                "repo": f["_repo"],
                "rule": rule_key(f),
                "finding": {k: v for k, v in f.items() if k != "_repo"},
            }
        )
    out.sort(
        key=lambda x: x["item_id"]
    )  # a fixed, arbitrary order, so scoring is not biased by grouping
    return out


class Recorder:
    """Wraps a client to keep the raw reply, so rejected answers can be inspected later."""

    def __init__(self, inner: LLMClient) -> None:
        self.inner, self.model, self.last = inner, inner.model, ""

    def complete(self, system: str, user: str) -> str:
        self.last = ""
        self.last = self.inner.complete(system, user)
        return self.last


def run_generation(
    items: list[dict[str, Any]],
    kb: KnowledgeBase,
    client: LLMClient,
    max_calls: int,
    on_item: Callable[[int, int, dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    """Run every item through the product's own `suggest()` (prompt, contract, patch check) and record it."""
    rec = Recorder(client)
    results = []
    for i, it in enumerate(items[:max_calls], 1):
        f = finding_from_dict(it["finding"])
        sn = f.location.snippet
        code = CodeContext(sn, f.location.start_line) if has_code(it["finding"]) else None
        res = suggest(f, kb, rec, code)
        row = {
            **it,
            "result": asdict(res),
            "raw_reply": rec.last if res.source == "static" else None,
        }
        results.append(row)
        if on_item:
            on_item(i, len(items), row)
    return results


def run_meta(model: str) -> dict[str, Any]:
    return {"model": model, "prompt_version": PROMPT_VERSION, "date": date.today().isoformat()}


# ---- scoring --------------------------------------------------------------------------------------------


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion: honest about small samples, unlike k/n alone."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def validate_scores(scores: dict[str, Any]) -> list[str]:
    """Problems with one item's scores (empty list = fine)."""
    problems = []
    for key in REQUIRED:
        if scores.get(key) is None:
            problems.append(f"{key} is missing")
    for key, allowed in SCALES.items():
        v = scores.get(key)
        if v is not None and v not in allowed:
            problems.append(f"{key}={v!r} is not one of {allowed}")
    return problems


def _rate(hits: int, n: int) -> dict[str, Any]:
    lo, hi = wilson(hits, n)
    return {
        "k": hits,
        "n": n,
        "rate": round(hits / n, 3) if n else None,
        "ci95": [round(lo, 3), round(hi, 3)],
    }


def report(
    results: list[dict[str, Any]], scores: dict[str, dict[str, Any]], meta: dict[str, Any]
) -> dict[str, Any]:
    """Turn hand scores into the numbers to publish. Refuses unscored or malformed data."""
    by_id = {r["item_id"]: r for r in results}
    unknown = sorted(set(scores) - set(by_id))
    if unknown:
        raise ValueError(f"scores for items that are not in the results: {unknown[:3]}")
    missing = sorted(set(by_id) - set(scores))
    if missing:
        raise ValueError(
            f"{len(missing)} of {len(by_id)} items are not scored yet (e.g. {missing[:3]})"
        )
    for iid, sc in scores.items():
        bad = validate_scores(sc)
        if bad:
            raise ValueError(f"item {iid}: {'; '.join(bad)}")

    rows = [(by_id[i], scores[i]) for i in sorted(scores)]
    ai = [(r, s) for r, s in rows if r["result"]["source"] == "ai"]
    degraded = Counter(
        (r["result"]["degraded_reason"] or "unknown").split(":")[0].split("(")[0].strip()
        for r, _ in rows
        if r["result"]["source"] == "static"
    )
    out: dict[str, Any] = {
        "meta": meta,
        "items": len(rows),
        "answered_by_model": len(ai),
        "fell_back_to_reference_text": len(rows) - len(ai),
        "fallback_reasons": dict(degraded),
        "caveat": f"n={len(ai)} scored AI answers: each interval below is wide; treat differences smaller than it as noise.",
    }
    n = len(ai)
    out["ai"] = {
        "fix_correct (score 2)": _rate(sum(s["fix_correct"] == 2 for _, s in ai), n),
        "fix_acceptable (score >=1)": _rate(sum(s["fix_correct"] >= 1 for _, s in ai), n),
        "explanation_accurate (score 2)": _rate(
            sum(s["explanation_accurate"] == 2 for _, s in ai), n
        ),
        "unsafe_suggestion": _rate(sum(s["unsafe"] == 1 for _, s in ai), n),
        "hallucinated_reference": _rate(sum(s["hallucination"] == 1 for _, s in ai), n),
    }
    with_patch = [(r, s) for r, s in ai if r["result"]["suggested_patch"]]
    verified = sum(r["result"]["patch_status"] == "verified" for r, _ in with_patch)
    scored_patches = [s for _, s in with_patch if s.get("patch_correct") is not None]
    out["patches"] = {
        "answers_with_a_patch": _rate(len(with_patch), n),
        "patch_matches_the_code (automatic check)": _rate(verified, len(with_patch)),
        "patch_correct (score 2, hand-scored)": _rate(
            sum(s["patch_correct"] == 2 for s in scored_patches), len(scored_patches)
        ),
        "patch_helpful (score >=1, hand-scored)": _rate(
            sum(s["patch_correct"] >= 1 for s in scored_patches), len(scored_patches)
        ),
    }
    cats: dict[str, list[int]] = defaultdict(list)
    for r, s in ai:
        cats[r["finding"]["taxonomy"]["category"]].append(int(s["fix_correct"] == 2))
    out["by_category"] = {c: _rate(sum(v), len(v)) for c, v in sorted(cats.items())}
    conf: dict[str, list[int]] = defaultdict(list)
    for r, s in ai:
        conf[r["result"]["confidence"]].append(int(s["fix_correct"] == 2))
    out["calibration (fix_correct by the model's own confidence)"] = {
        c: _rate(sum(v), len(v)) for c, v in sorted(conf.items())
    }
    paired = [
        (s["fix_correct"], s["static_fix_correct"])
        for _, s in ai
        if s.get("static_fix_correct") is not None
    ]
    if paired:
        out["versus_reference_text"] = {
            "items_scored_both_ways": len(paired),
            "reference_fix_correct (score 2)": _rate(sum(b == 2 for _, b in paired), len(paired)),
            "ai_better": sum(a > b for a, b in paired),
            "equal": sum(a == b for a, b in paired),
            "ai_worse": sum(a < b for a, b in paired),
        }
    return out


def markdown_table(rep: dict[str, Any]) -> str:
    """The README table, generated from a report (never typed by hand)."""
    m = rep["meta"]
    lines = [
        f"Measured {m['date']} with `{m['model']}` (prompt `{m['prompt_version']}`), {rep['items']} sampled findings, "
        f"{rep['answered_by_model']} answered by the model, {rep['fell_back_to_reference_text']} fell back to reference text.",
        "",
        "| Measure | Result | 95% interval | n |",
        "|---|---:|---:|---:|",
    ]
    for section in ("ai", "patches"):
        for name, r in rep[section].items():
            pct = "n/a" if r["rate"] is None else f"{r['rate']:.0%} ({r['k']}/{r['n']})"
            lines.append(
                f"| {name} | {pct} | {r['ci95'][0]:.0%} to {r['ci95'][1]:.0%} | {r['n']} |"
            )
    lines += ["", rep["caveat"]]
    return "\n".join(lines)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows),
        encoding="utf-8",
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def find_repo_label(export: dict[str, Any]) -> str:
    return str(export.get("source", "unknown"))
