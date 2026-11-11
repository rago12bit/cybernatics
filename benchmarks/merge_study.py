"""Merge accuracy: are the reports Bulwark merges really one defect, and which duplicates does it miss?

    python -m benchmarks.merge_study collect --label v1    # scan the pinned corpus and keep every raw report (needs Docker)
    python -m benchmarks.merge_study sample <raw.json.gz>  # draw the pairs to label: an answer key and a labelling page
    python -m benchmarks.merge_study score <key.json> --labels raghav=<labels.csv> [--labels other=<labels.csv>]

The deduplication rate says how much shorter the list gets, not whether the merges are right. This is the
missing half: a person looks at pairs of raw reports, without being told what Bulwark did with them, and says
whether they are one defect. Merged pairs give precision; pairs Bulwark left apart, but which look alike, give
the missed-merge rate. Protocol, codebook and results: docs/evaluation-merge-accuracy.md.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import date
from itertools import combinations
from pathlib import Path
from typing import Any

from benchmarks.corpus.run import CACHE, fetch_repo, load_manifest
from benchmarks.owasp.score import wilson
from core.correlation import cwe_family, partition
from core.correlation import engine as eng
from core.models import Category, Finding, finding_from_dict
from core.redact import redact_near_secrets, redact_secret_findings

RESULTS = Path(__file__).resolve().parent / "results"
# Raw reports are kept out of the repository: they are not redacted.
RAW_DIR = CACHE.parent / "merge-study"

SEED = 20261111
# A pair Bulwark left apart is a look-alike when it shares a weakness family this many lines apart.
NEAR_LINES = 10
LABELS = ("same", "different", "unsure")
MERGED = ("code", "dependency", "same-tool")
NEAR = ("near-code", "near-dependency")
#: How many units to draw per stratum (None: all of them) and how many pairs to check in each merged group.
QUOTA: dict[str, int | None] = {
    "code": None,
    "dependency": 100,
    "same-tool": 30,
    "near-code": 50,
    "near-dependency": 50,
}
PAIRS_PER_GROUP = {"code": 3, "dependency": 1, "same-tool": 1}

CODEBOOK = [
    "Answer one question: are these two reports the same defect? That is, the same flaw, with the same root cause, at the same place.",
    "Dependencies: the same package, the same installed version and the same vulnerability, declared in the same manifest or lock file. One advisory under two ids (a CVE and a GHSA) is the same. Two different vulnerabilities are different, even when one upgrade fixes both.",
    "The same vulnerable package version declared in two different manifests is two places to fix: different. Say so in the note.",
    "Code: the same file and the same flaw, at one statement or at the statements that make the flaw together (a query built on one line and run on the next). The same kind of flaw at two separate places is different. Two different flaws on one line are different.",
    "Secrets: a secret scanner and a code scanner pointing at the same hard-coded value are the same.",
    "Infrastructure and containers: the same resource or instruction with the same misconfiguration is the same. Two different misconfigurations of one resource are different.",
    "Open the source link when the reports alone do not settle it. Choose Unsure only if it still does not.",
    "Judge the reports, not what a tool should have done. You are not told whether Bulwark merged the pair.",
]


# ---- collect ----------------------------------------------------------------------------
def collect(label: str, only: list[str] | None = None) -> Path:
    from core.scan import ADAPTERS, DEFAULT_TOOLS, detect_context, threaded_executor
    from core.source import materialize

    rows: list[dict[str, Any]] = []
    for r in load_manifest()["repos"]:
        if only and r["name"] not in only:
            continue
        row: dict[str, Any] = {
            "repo": r["name"],
            "kind": r["kind"],
            "commit": r["commit"],
            "url": r["url"],
        }
        try:
            with materialize(str(fetch_repo(r))) as ws:
                ctx = detect_context(ws)
                # The tools, and below the order, that core.scan.scan correlates.
                tools = [t for t in DEFAULT_TOOLS if ADAPTERS[t].applies_to(ctx)]
                outcomes = {o.tool: o for o in threaded_executor(tools, ws)}
            raw = [f for t in tools for f in outcomes[t].findings]
            row |= {"tool_status": {t: outcomes[t].status for t in tools}, "raw": [f.to_dict() for f in raw],
                    "unique": len(partition(raw))}  # fmt: skip
        except Exception as exc:  # noqa: BLE001 - a repo that cannot be scanned is a data point
            row |= {"error": f"{type(exc).__name__}: {exc}", "raw": []}
        failed = _failed(row)
        print(
            f"{r['name']:30} {len(row['raw']):5} raw  {row.get('unique', '-'):>5} unique"
            + (f"  FAILED: {', '.join(failed)}" if failed else ""),
            file=sys.stderr,
        )
        rows.append(row)
    doc = {
        "label": label, "collected_on": date.today().isoformat(),
        "images": {t: ADAPTERS[t].spec.image for t in DEFAULT_TOOLS},
        "correlation_params": {"line_window": eng.LINE_WINDOW, "adjacent": eng.ADJACENT,
                               "snippet_overlap": eng.SNIPPET_OVERLAP, "min_tokens": eng.MIN_TOKENS},
        "repos": rows,
    }  # fmt: skip
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    out = RAW_DIR / f"{doc['collected_on']}-{label}.raw.json.gz"
    with gzip.open(out, "wt") as fh:
        json.dump(doc, fh)
    return out


def _failed(row: dict[str, Any]) -> list[str]:
    """What did not run for a repository. A study over a scan with holes in it measures the holes."""
    if row.get("error"):
        return [row["error"]]
    return [f"{t} ({s})" for t, s in row.get("tool_status", {}).items() if s != "ok"]


# ---- what there is to label --------------------------------------------------------------
def _tools(reports: list[Finding]) -> set[str]:
    return {t for f in reports for t in f.evidence.reported_by}


def _ids(f: Finding) -> set[str]:
    return {x.upper() for x in (*f.taxonomy.cve, *f.taxonomy.aliases)}


def _gap(a: Finding, b: Finding) -> int:
    return max(
        0,
        max(a.location.start_line, b.location.start_line)
        - min(a.location.end_line, b.location.end_line),
    )


def stratum(group: list[Finding]) -> str:
    """Which kind of merge a group of two or more reports is."""
    if len(_tools(group)) == 1:
        return "same-tool"  # one tool repeating itself, or two of its rules on one defect
    return "dependency" if any(f.package for f in group) else "code"


def near_misses(
    raw: list[Finding], part_of: dict[int, int], parts: list[list[Finding]]
) -> Iterator[tuple[str, str, int, int]]:
    """Pairs from different tools that Bulwark left apart but a reader might call one defect:
    (stratum, why, i, j), i and j being positions in `raw`.

    Code: the same file and either one weakness family within NEAR_LINES (the line window may have
    been too narrow) or adjacent lines whatever the weakness (the tools may have named it
    differently). Similar code is not a signal on its own: with names masked, most statements
    overlap. Dependencies: a shared id, or one package version that neither tool's report was
    matched on (an alias one of them does not list)."""
    by_file: dict[str, list[int]] = defaultdict(list)
    by_package: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, f in enumerate(raw):
        if f.taxonomy.category is Category.DAST:
            continue  # never merged: no file, line or code to compare
        if f.package:
            by_package[(f.package.ecosystem, f.package.name)].append(i)
        else:
            by_file[f.location.path].append(i)
    for idxs in by_file.values():
        for i, j in combinations(idxs, 2):
            a, b = raw[i], raw[j]
            if part_of[i] == part_of[j] or _tools([a]) & _tools([b]) or _gap(a, b) > NEAR_LINES:
                continue
            if cwe_family(a) & cwe_family(b):
                yield "near-code", "same weakness family", i, j
            elif _gap(a, b) <= eng.ADJACENT:
                yield "near-code", "adjacent lines", i, j
    for idxs in by_package.values():
        for i, j in combinations(idxs, 2):
            a, b = raw[i], raw[j]
            if part_of[i] == part_of[j] or _tools([a]) & _tools([b]):
                continue
            assert a.package and b.package
            if _ids(a) & _ids(b):  # a shared id, yet apart: another version, or the same-rule guard
                yield "near-dependency", "shared id", i, j
            elif (
                a.package.version == b.package.version
                and len(_tools(parts[part_of[i]])) == len(_tools(parts[part_of[j]])) == 1
            ):
                yield "near-dependency", "same version, neither matched by another tool", i, j


def _report(f: Finding, url: str, commit: str) -> dict[str, Any]:
    loc = f.location
    link = ""
    if loc.path and url.startswith("https://github.com/"):
        link = f"{url}/blob/{commit}/{loc.path}" + (
            f"#L{loc.start_line}-L{loc.end_line}" if loc.start_line else ""
        )
    return {
        "tools": f.evidence.reported_by, "rules": sorted({r for rs in f.evidence.rule_ids.values() for r in rs}),
        "title": f.title, "description": f.description[:700], "category": f.taxonomy.category.value,
        "path": loc.path, "start_line": loc.start_line, "end_line": loc.end_line, "snippet": loc.snippet[:2000], "link": link,
        "cwe": list(f.taxonomy.cwe), "ids": sorted(_ids(f)), "severity": f.scoring.native_severity,
        "package": {"ecosystem": f.package.ecosystem, "name": f.package.name, "version": f.package.version} if f.package else None,
    }  # fmt: skip


def draw(
    doc: dict[str, Any], seed: int = SEED, quota: dict[str, int | None] | None = None
) -> dict[str, Any]:
    """The answer key: every stratum's size, and the pairs drawn from it, in the order they are shown."""
    quota = {**QUOTA, **(quota or {})}
    rng = random.Random(seed)
    units: dict[str, list[dict[str, Any]]] = {s: [] for s in (*MERGED, *NEAR)}
    repos = []
    for row in doc["repos"]:
        raw = [finding_from_dict(d) for d in row["raw"]]
        # What the rater sees is redacted like any Bulwark output; what is correlated above is not.
        shown = redact_secret_findings(
            redact_near_secrets([finding_from_dict(d) for d in row["raw"]])
        )
        parts = partition(raw)
        index = {id(f): i for i, f in enumerate(raw)}
        part_of = {index[id(f)]: p for p, part in enumerate(parts) for f in part}
        repos.append(
            {k: row.get(k) for k in ("repo", "kind", "commit", "url", "error")}
            | {"raw": len(raw), "unique": len(parts), "failed": _failed(row)}
        )

        def pair(
            i: int, j: int, row: dict[str, Any] = row, shown: list[Finding] = shown
        ) -> dict[str, Any]:
            return {
                "pair": [i, j],
                "reports": [_report(shown[k], row["url"], row["commit"]) for k in (i, j)],
            }

        for p, part in enumerate(parts):
            if len(part) > 1:
                units[stratum(part)].append({"repo": row["repo"], "group": f"{row['repo']}#{p}", "size": len(part),
                                             "pairs": [pair(index[id(a)], index[id(b)]) for a, b in combinations(part, 2)]})  # fmt: skip
        for s, why, i, j in near_misses(raw, part_of, parts):
            units[s].append(
                {
                    "repo": row["repo"],
                    "group": f"{row['repo']}~{i}-{j}",
                    "why": why,
                    "pairs": [pair(i, j)],
                }
            )

    items: list[dict[str, Any]] = []
    strata: dict[str, dict[str, Any]] = {}
    for s, pop in units.items():
        n = quota[s]
        chosen = pop if n is None or n >= len(pop) else rng.sample(pop, n)
        strata[s] = {"kind": "merged" if s in MERGED else "near", "population": len(pop), "sampled": len(chosen),
                     "by_repo": dict(Counter(u["repo"] for u in pop))}  # fmt: skip
        for u in chosen:
            k = PAIRS_PER_GROUP.get(s, 1)
            for pr in u["pairs"] if len(u["pairs"]) <= k else rng.sample(u["pairs"], k):
                # Which report is on the left says nothing.
                reports = pr["reports"] if rng.random() < 0.5 else pr["reports"][::-1]
                i, j = pr["pair"]
                items.append({"id": hashlib.sha256(f"{u['repo']}|{i}|{j}".encode()).hexdigest()[:10], "stratum": s,
                              "repo": u["repo"], "group": u["group"], "why": u.get("why", ""), "reports": reports})  # fmt: skip
    # Merged and left-apart pairs are interleaved: the rater cannot tell which is which.
    rng.shuffle(items)
    return {"study": f"{doc['collected_on']}-{doc['label']}", "drawn_on": date.today().isoformat(), "seed": seed,
            "near": {"lines": NEAR_LINES, "adjacent": eng.ADJACENT}, "correlation_params": doc.get("correlation_params"),
            "images": doc.get("images"), "repos": repos, "strata": strata, "items": items}  # fmt: skip


# ---- score -------------------------------------------------------------------------------
def read_labels(path: Path, key: dict[str, Any]) -> dict[str, str]:
    known = {it["id"] for it in key["items"]}
    out: dict[str, str] = {}
    with path.open(newline="") as fh:
        for row in csv.DictReader(fh):
            item, label = row["item"].strip(), row["label"].strip().lower()
            if not label:
                continue
            if item not in known or label not in LABELS:
                raise ValueError(f"{path.name}: unknown item or label: {item!r} {label!r}")
            out[item] = label
    return out


def _rate(k: int, n: int) -> dict[str, Any]:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else None, "ci95": [lo, hi]}


def _verdict(labels: set[str]) -> str:
    """A group's answer from its checked pairs: one different pair makes the merge wrong."""
    return next((x for x in ("", "different", "unsure") if x in labels), "same") or "unlabelled"


def score_rater(key: dict[str, Any], labels: dict[str, str]) -> dict[str, Any]:
    """Precision per merged stratum (a group is right when every checked pair in it is the same defect),
    the missed-merge rate per left-apart stratum, and both pooled over the corpus."""
    verdicts: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for it in key["items"]:
        verdicts[it["stratum"]][it["group"]].add(labels.get(it["id"], ""))
    out: dict[str, Any] = {"labelled": len(labels), "items": len(key["items"]), "strata": {}}
    for s, groups in verdicts.items():
        got = Counter(_verdict(v) for v in groups.values())
        same, diff, unsure = got["same"], got["different"], got["unsure"]
        merged = s in MERGED
        out["strata"][s] = {
            "population": key["strata"][s]["population"], "same": same, "different": diff, "unsure": unsure, "unlabelled": got["unlabelled"],
            # Precision: merged groups that are one defect. Missed: left-apart pairs that are one defect.
            ("precision" if merged else "missed"): _rate(same, same + diff),
            ("precision_unsure_wrong" if merged else "missed_unsure_same"): _rate(same if merged else same + unsure, same + diff + unsure),
        }  # fmt: skip
    for name, strata, field in (("precision", MERGED, "precision"), ("missed", NEAR, "missed")):
        rows = [
            (v["population"], v[field], v)
            for s, v in out["strata"].items()
            if s in strata and v[field]["n"]
        ]
        total = sum(n for n, _, _ in rows)
        if not total:
            continue
        # A stratum labelled in full is known exactly for this corpus; a sampled one carries its interval.
        exact = [v["same"] + v["different"] == n for n, _, v in rows]
        out[name] = {
            "rate": sum(n * r["rate"] for n, r, _ in rows) / total,
            "ci95": [sum(n * (r["rate"] if e else r["ci95"][b]) for (n, r, _), e in zip(rows, exact, strict=True)) / total for b in (0, 1)],
            "units": total,
            "estimated_" + ("wrong_merges" if name == "precision" else "missed_merges"): round(
                sum(n * ((1 - r["rate"]) if name == "precision" else r["rate"]) for n, r, _ in rows), 1),
        }  # fmt: skip
    return out


def kappa(a: dict[str, str], b: dict[str, str]) -> dict[str, Any]:
    """Cohen's kappa over the items both raters labelled."""
    both = sorted(set(a) & set(b))
    if not both:
        return {"items": 0, "agreement": None, "kappa": None, "disagreements": []}
    po = sum(a[i] == b[i] for i in both) / len(both)
    ca, cb = Counter(a[i] for i in both), Counter(b[i] for i in both)
    pe = sum(ca[x] * cb[x] for x in LABELS) / len(both) ** 2
    return {"items": len(both), "agreement": po, "kappa": None if pe == 1 else (po - pe) / (1 - pe),
            "disagreements": [i for i in both if a[i] != b[i]]}  # fmt: skip


def score(key: dict[str, Any], labels: dict[str, dict[str, str]]) -> dict[str, Any]:
    raters = sorted(labels)
    return {"study": key["study"], "seed": key["seed"], "scored_on": date.today().isoformat(),
            "raters": {r: score_rater(key, labels[r]) for r in raters},
            "agreement": {f"{x}/{y}": kappa(labels[x], labels[y]) for x, y in combinations(raters, 2)}}  # fmt: skip


def markdown(result: dict[str, Any]) -> str:
    def pc(r: dict[str, Any]) -> str:
        return (
            "n/a"
            if r["rate"] is None
            else f"{r['rate']:.1%} ({r['ci95'][0]:.1%}–{r['ci95'][1]:.1%})"
        )

    tables = (
        (
            "precision",
            MERGED,
            "Merged by Bulwark",
            "Precision",
            "Merge precision, all merged groups",
        ),
        (
            "missed",
            NEAR,
            "Left apart by Bulwark",
            "One defect after all",
            "Missed among look-alikes",
        ),
    )
    lines = []
    for rater, res in result["raters"].items():
        lines += [f"### Rater: {rater} ({res['labelled']} of {res['items']} pairs labelled)", ""]
        for field, strata, title, rate, pooled in tables:
            rows = [(s, res["strata"][s]) for s in strata if s in res["strata"]]
            if not rows:
                continue
            lines += [f"| {title} | In corpus | Same | Different | Unsure | {rate} (95% CI) |", "|---|---:|---:|---:|---:|---|"]  # fmt: skip
            lines += [f"| {s} | {v['population']} | {v['same']} | {v['different']} | {v['unsure']} | {pc(v[field])} |" for s, v in rows]  # fmt: skip
            if field in res:
                lines += ["", f"**{pooled}:** {pc(res[field])} over {res[field]['units']} in the corpus."]  # fmt: skip
            lines.append("")
    for pair, k in result["agreement"].items():
        if k["items"]:
            kap = "undefined" if k["kappa"] is None else f"{k['kappa']:.2f}"
            lines.append(
                f"**Agreement {pair}:** {k['agreement']:.1%} of {k['items']} pairs, Cohen's kappa {kap}."
            )
    return "\n".join(lines)


# ---- the labelling page ------------------------------------------------------------------
def page(key: dict[str, Any]) -> str:
    """One self-contained file. It carries the reports and nothing about what Bulwark did with them."""
    data = {
        "study": key["study"],
        "codebook": CODEBOOK,
        "items": [{"id": it["id"], "reports": it["reports"]} for it in key["items"]],
    }
    return _PAGE.replace("__DATA__", json.dumps(data).replace("</", "<\\/"))


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Merge study labelling</title>
<style>
:root{--bg:#fbfbf8;--panel:#fff;--ink:#1b1b17;--ink2:#55564e;--rule:#d6d6cc;--accent:#0b7a5e;--warn:#9a6410;--bad:#b3261e;--code:#f0f0ea}
@media (prefers-color-scheme:dark){:root{--bg:#131310;--panel:#1c1c17;--ink:#ecebe4;--ink2:#a2a396;--rule:#3b3b33;--accent:#12b58b;--warn:#e8b74f;--bad:#f2877f;--code:#24241e}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:20px 16px 48px}h1{font-size:20px;margin:0}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:12px 0}.grow{flex:1}
progress{width:100%;height:6px;accent-color:var(--accent)}
input,button{font:inherit;color:inherit;background:var(--panel);border:1px solid var(--rule);border-radius:6px;padding:7px 12px}
button{cursor:pointer}button:hover{border-color:var(--accent)}button.on{background:var(--accent);border-color:var(--accent);color:#fff}
details{border:1px solid var(--rule);border-radius:8px;padding:8px 14px;background:var(--panel);margin:12px 0}summary{cursor:pointer;font-weight:600}
details li{margin:4px 0;color:var(--ink2)}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media (max-width:820px){.pair{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--rule);border-radius:8px;padding:14px;min-width:0}
.tool{font:12px ui-monospace,Menlo,monospace;color:var(--accent);overflow-wrap:anywhere}.title{font-weight:600;margin:6px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:8px 0;font-size:13px}dt{color:var(--ink2)}dd{margin:0;overflow-wrap:anywhere}
pre{background:var(--code);border-radius:6px;padding:10px;overflow:auto;font:12.5px/1.45 ui-monospace,Menlo,monospace;max-height:260px;margin:8px 0;white-space:pre}
.desc{color:var(--ink2);font-size:13px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:160px;overflow:auto}
a{color:var(--accent)}.answer{position:sticky;bottom:0;background:var(--bg);padding:12px 0;border-top:1px solid var(--rule);margin-top:14px}
.muted{color:var(--ink2);font-size:13px}kbd{border:1px solid var(--rule);border-radius:4px;padding:0 5px;font-size:12px}
#note{flex:1;min-width:200px}#done{display:none;border:1px solid var(--accent);border-radius:8px;padding:14px;margin:12px 0}
</style></head><body><main>
<h1>Are these two reports the same defect?</h1>
<div class="bar"><span id="count" class="muted"></span><span class="grow"><progress id="prog" value="0" max="1"></progress></span>
<label class="muted">Your name <input id="rater" size="12" autocomplete="off"></label><button id="save">Download labels (CSV)</button></div>
<details><summary>How to decide</summary><ol id="codebook"></ol></details>
<div id="done"></div>
<div class="pair" id="pair"></div>
<div class="answer"><div class="bar">
<button id="b-same">Same <kbd>S</kbd></button><button id="b-different">Different <kbd>D</kbd></button><button id="b-unsure">Unsure <kbd>U</kbd></button>
<input id="note" placeholder="Note (optional)" autocomplete="off">
<button id="back">Back <kbd>&larr;</kbd></button><button id="next">Next <kbd>&rarr;</kbd></button></div>
<div class="muted" id="status"></div></div>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("data").textContent), K = "merge-study:" + D.study, $ = (id) => document.getElementById(id);
let S = { at: 0, rater: "", labels: {}, notes: {} };
try { S = Object.assign(S, JSON.parse(localStorage.getItem(K) || "{}")); } catch (e) { /* private window: labels live until the tab closes */ }
const keep = () => { try { localStorage.setItem(K, JSON.stringify(S)); } catch (e) { $("status").textContent = "This browser is not saving progress. Download the CSV before closing the tab."; } };
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
for (const rule of D.codebook) $("codebook").append(el("li", "", rule));
$("rater").value = S.rater;
function row(dl, k, v) { if (v) { dl.append(el("dt", "", k), el("dd", "", v)); } }
function card(r) {
  const c = el("div", "card");
  c.append(el("div", "tool", r.tools.join(", ") + (r.rules.length ? " · " + r.rules.join(", ") : "")), el("div", "title", r.title));
  const dl = el("dl");
  if (r.package) row(dl, "Package", r.package.ecosystem + " " + r.package.name + " " + r.package.version);
  row(dl, "Ids", r.ids.join(", ")); row(dl, "Weakness", r.cwe.join(", ")); row(dl, "Kind", r.category);
  row(dl, "Severity", Object.entries(r.severity).map(([t, s]) => t + ": " + s).join(", "));
  if (r.path) {
    const where = r.path + (r.start_line ? ":" + r.start_line + (r.end_line > r.start_line ? "–" + r.end_line : "") : "");
    const dd = el("dd");
    if (r.link.startsWith("https://github.com/")) { const a = el("a", "", where); a.href = r.link; a.target = "_blank"; a.rel = "noopener noreferrer"; dd.append(a); } else dd.textContent = where;
    dl.append(el("dt", "", "Where"), dd);
  }
  c.append(dl);
  if (r.snippet) c.append(el("pre", "", r.snippet));
  if (r.description && r.description !== r.title) c.append(el("div", "desc", r.description));
  return c;
}
function show() {
  const n = D.items.length, done = Object.keys(S.labels).length;
  S.at = Math.max(0, Math.min(S.at, n - 1));
  const it = D.items[S.at];
  $("pair").replaceChildren(...it.reports.map(card));
  $("count").textContent = "Pair " + (S.at + 1) + " of " + n + " · " + done + " labelled";
  $("prog").value = done / n;
  for (const l of ["same", "different", "unsure"]) $("b-" + l).classList.toggle("on", S.labels[it.id] === l);
  $("note").value = S.notes[it.id] || "";
  $("done").style.display = done === n ? "block" : "none";
  $("done").textContent = done === n ? "All " + n + " pairs are labelled. Download the CSV and keep it with the study's files." : "";
  window.scrollTo(0, 0);
}
function answer(l) {
  const it = D.items[S.at];
  S.labels[it.id] = l;
  const next = D.items.findIndex((x, i) => i > S.at && !S.labels[x.id]);
  S.at = next >= 0 ? next : Math.min(S.at + 1, D.items.length - 1);
  keep(); show();
}
function move(d) { S.at += d; keep(); show(); }
for (const l of ["same", "different", "unsure"]) $("b-" + l).onclick = () => answer(l);
$("back").onclick = () => move(-1); $("next").onclick = () => move(1);
$("note").oninput = () => { S.notes[D.items[S.at].id] = $("note").value; keep(); };
$("rater").oninput = () => { S.rater = $("rater").value.trim(); keep(); };
document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.metaKey || e.ctrlKey || e.altKey) return;
  const k = e.key.toLowerCase();
  if (k === "s") answer("same"); else if (k === "d") answer("different"); else if (k === "u") answer("unsure");
  else if (k === "arrowleft") move(-1); else if (k === "arrowright") move(1);
});
const q = (v) => '"' + String(v || "").replace(/"/g, '""') + '"';
$("save").onclick = () => {
  const rows = ["item,label,note"].concat(D.items.filter((it) => S.labels[it.id]).map((it) => [it.id, S.labels[it.id], q(S.notes[it.id])].join(",")));
  const a = el("a"); a.href = URL.createObjectURL(new Blob([rows.join("\\n") + "\\n"], { type: "text/csv" }));
  a.download = "merge-study-" + D.study + "-" + (S.rater || "rater").replace(/[^A-Za-z0-9_-]/g, "") + ".labels.csv";
  document.body.append(a); a.click(); a.remove();
};
show();
</script></body></html>
"""


# ---- CLI ---------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--label", default="v1")
    c.add_argument("--repo", action="append", help="only this corpus repository (repeatable)")
    s = sub.add_parser("sample")
    s.add_argument("raw", type=Path)
    s.add_argument("--seed", type=int, default=SEED)
    for name in QUOTA:
        s.add_argument(
            f"--{name}",
            type=int,
            default=None,
            help=f"units to draw from {name} (default: {QUOTA[name] or 'all'})",
        )
    k = sub.add_parser("score")
    k.add_argument("key", type=Path)
    k.add_argument("--labels", action="append", required=True, metavar="RATER=FILE")
    args = ap.parse_args(argv)

    if args.cmd == "collect":
        out = collect(args.label, args.repo)
        print(f"wrote {out}", file=sys.stderr)
        with gzip.open(out, "rt") as fh:
            if any(_failed(row) for row in json.load(fh)["repos"]):
                print("Some tools did not run (see FAILED above): fix that before sampling.", file=sys.stderr)  # fmt: skip
                return 1
    elif args.cmd == "sample":
        with gzip.open(args.raw, "rt") as fh:
            doc = json.load(fh)
        quota = {n: v for n in QUOTA if (v := getattr(args, n.replace("-", "_"))) is not None}
        key = draw(doc, args.seed, quota)
        for r in key["repos"]:
            if r["failed"]:
                print(f"warning: {r['repo']}: did not run: {', '.join(r['failed'])}", file=sys.stderr)  # fmt: skip
        base = RESULTS / f"merge-study-{key['study']}"
        base.with_name(base.name + ".key.json").write_text(json.dumps(key, indent=1) + "\n")
        base.with_name(base.name + ".label.html").write_text(page(key))
        for name, st in key["strata"].items():
            print(f"{name:16} {st['sampled']:4} of {st['population']:5}", file=sys.stderr)
        print(
            f"{len(key['items'])} pairs to label: {base.name}.label.html (key: {base.name}.key.json)",
            file=sys.stderr,
        )
    else:
        key = json.loads(args.key.read_text())
        labels = {r: read_labels(Path(p), key) for r, p in (x.split("=", 1) for x in args.labels)}
        result = score(key, labels)
        out = args.key.with_name(args.key.name.replace(".key.json", ".scores.json"))
        out.write_text(json.dumps(result, indent=1) + "\n")
        print(markdown(result))
        print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
