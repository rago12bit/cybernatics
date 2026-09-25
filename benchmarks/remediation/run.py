#!/usr/bin/env python3
"""Fix-quality evaluation driver (Week 14). Protocol: docs/evaluation-remediation.md.

python benchmarks/remediation/run.py sample   EXPORT.json ... [-n 50] [--seed 1]   # no model, no network
python benchmarks/remediation/run.py generate --sample sample.jsonl [--dry-run]    # needs a model key
python benchmarks/remediation/run.py scorer   --results runs/X/results.jsonl       # writes a scoring page
python benchmarks/remediation/run.py report   --results ... --scores scores.json   # numbers + README table
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from core.llm import evaluation as ev  # noqa: E402
from core.llm.service import static_suggestion  # noqa: E402
from core.models import finding_from_dict  # noqa: E402

HERE = Path(__file__).resolve().parent


def _kb():  # type: ignore[no-untyped-def]
    """An in-memory knowledge base built from the committed corpus: needs no database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from sqlalchemy.pool import StaticPool

    from core.persistence.models import Base
    from core.rag.corpus_io import read_corpus
    from core.rag.store import KnowledgeBase, load_corpus

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    s = Session(engine)
    load_corpus(s, read_corpus())
    return KnowledgeBase(s)


def cmd_sample(a: argparse.Namespace) -> None:
    seen: dict[tuple[str, str], dict] = {}
    for p in a.exports:
        doc = json.loads(Path(p).read_text())
        label = ev.find_repo_label(doc)
        for f in doc["findings"]:
            seen.setdefault(
                (label, f["id"]), {**f, "_repo": label}
            )  # the same repo scanned twice counts once
    pool = list(seen.values())
    sample = ev.select_sample(pool, a.n, a.seed, a.code_share)
    ev.write_jsonl(Path(a.out), sample)
    from collections import Counter

    print(f"{len(pool)} unique findings -> sample of {len(sample)} written to {a.out}")
    print("by category:", dict(Counter(s["finding"]["taxonomy"]["category"] for s in sample)))
    print(
        "by repo:",
        dict(Counter(s["repo"].split("/")[-1] for s in sample)),
        "| distinct rules:",
        len({s["rule"] for s in sample}),
    )


def cmd_generate(a: argparse.Namespace) -> None:
    from core.llm.client import LLMConfig, make_client
    from core.llm.prompt import CodeContext, build_prompt
    from core.rag.retrieve import context_for

    items = ev.read_jsonl(Path(a.sample))[: a.max_calls]
    kb = _kb()
    if a.dry_run:  # prints what WOULD be sent; contacts nothing and needs no key
        chars = 0
        for it in items:
            f = finding_from_dict(it["finding"])
            code = (
                CodeContext(f.location.snippet, f.location.start_line)
                if ev.has_code(it["finding"])
                else None
            )
            p = build_prompt(f, context_for(f, kb), code)
            chars += len(p.system) + len(p.user)
        print(
            f"{len(items)} calls; about {chars // 4:,} input tokens in total (characters / 4; a rough estimate)."
        )
        print("Output is capped at BULWARK_LLM_MAX_TOKENS per call (default 1500).")
        return
    cfg = LLMConfig.from_env()
    client = make_client(cfg)
    if client is None:
        sys.exit(
            "No model configured. Set BULWARK_LLM_ENABLED=1 and BULWARK_LLM_API_KEY (and `pip install 'bulwark-scan[llm]'`).\n"
            "Use --dry-run to see what would be sent without a key."
        )
    print(
        f"Model {client.model}: {len(items)} calls. Data leaves this machine (see docs/llm-remediation.md). Ctrl-C to stop."
    )
    results = ev.run_generation(
        items,
        kb,
        client,
        a.max_calls,
        lambda i, n, r: print(f"  {i}/{n} {r['result']['source']:6} {r['rule'][:60]}"),
    )
    out = (
        Path(a.out)
        if a.out
        else HERE / "runs" / f"{ev.run_meta(client.model)['date']}-{client.model}"
    )
    out.mkdir(parents=True, exist_ok=True)
    ev.write_jsonl(out / "results.jsonl", results)
    (out / "meta.json").write_text(json.dumps(ev.run_meta(client.model), indent=1) + "\n")
    print(f"wrote {out}/results.jsonl. Next: `run.py scorer --results {out}/results.jsonl`")


def cmd_scorer(a: argparse.Namespace) -> None:
    results = ev.read_jsonl(Path(a.results))
    kb = _kb()
    static = {}
    for r in results:
        f = finding_from_dict(r["finding"])
        from core.rag.retrieve import context_for

        s = static_suggestion(f, context_for(f, kb), "reference guidance")
        static[r["item_id"]] = {"explanation": s.explanation, "fix_summary": s.fix_summary}

    def slim(
        f: dict,
    ) -> dict:  # only what a person needs to judge the answer: no scores, evidence or risk data
        return {
            "title": f["title"],
            "description": f["description"],
            "location": {
                k: f["location"][k] for k in ("path", "start_line", "end_line", "snippet")
            },
            "taxonomy": {"category": f["taxonomy"]["category"], "cwe": f["taxonomy"]["cwe"]},
        }

    blind = [
        {
            "item_id": r["item_id"],
            "repo": r["repo"],
            "rule": r["rule"],
            "finding": slim(r["finding"]),
            "result": {
                "source": r["result"]["source"],
                "explanation": r["result"]["explanation"],
                "impact": r["result"]["impact"],
                "fix_summary": r["result"]["fix_summary"],
                "suggested_patch": r["result"]["suggested_patch"],
            },
        }
        for r in results
    ]
    payload = json.dumps(
        {"run": Path(a.results).parent.name, "items": blind, "static": static}, ensure_ascii=False
    )
    payload = payload.replace("<", "\\u003c").replace(
        "&", "\\u0026"
    )  # cannot close the script tag or start a comment
    out = Path(a.out or Path(a.results).with_name("scorer.html"))
    out.write_text(
        (HERE / "scorer_template.html").read_text().replace("__DATA__", payload), encoding="utf-8"
    )
    print(f"open {out} in a browser, score every item, click 'Download scores.json'")


def cmd_report(a: argparse.Namespace) -> None:
    results = ev.read_jsonl(Path(a.results))
    scores = json.loads(Path(a.scores).read_text())
    meta = json.loads(Path(a.results).with_name("meta.json").read_text())
    rep = ev.report(results, scores, meta)
    out = ROOT / "benchmarks" / "results" / f"remediation-{meta['date']}.json"
    out.write_text(json.dumps(rep, indent=2) + "\n")
    print(ev.markdown_table(rep))
    print(f"\nfull report: {out}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("exports", nargs="+")
    s.add_argument("-n", type=int, default=ev.DEFAULT_N)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--code-share", type=float, default=ev.DEFAULT_CODE_SHARE)
    s.add_argument("--out", default=str(HERE / "sample.jsonl"))
    s.set_defaults(fn=cmd_sample)
    g = sub.add_parser("generate")
    g.add_argument("--sample", default=str(HERE / "sample.jsonl"))
    g.add_argument("--out")
    g.add_argument("--max-calls", type=int, default=ev.DEFAULT_N)
    g.add_argument("--dry-run", action="store_true")
    g.set_defaults(fn=cmd_generate)
    c = sub.add_parser("scorer")
    c.add_argument("--results", required=True)
    c.add_argument("--out")
    c.set_defaults(fn=cmd_scorer)
    r = sub.add_parser("report")
    r.add_argument("--results", required=True)
    r.add_argument("--scores", required=True)
    r.set_defaults(fn=cmd_report)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
