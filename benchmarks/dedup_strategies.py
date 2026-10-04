"""What each deduplication strategy would do to real reports (plan §42.3, §60 "Deduplication").

    python -m benchmarks.dedup_strategies [--out benchmarks/results/dedup-strategies-2026-10-04.json]

For each real report vendored from DefectDojo's samples (and the project's own golden scan output),
this parses it with the import parser, takes the Issues a default import would make (one per distinct
fingerprint), and asks the dry run (`core.dedup.change.plan_change`) what each strategy would make of
them: how many Issues, how many merged, how many split.

This is a measurement of **what a strategy changes**, not of whether the change is *right*. Whether
two findings really are one defect needs a hand-labelled corpus (the plan's: duplicate pairs from
three tools across ten repositories), which does not exist yet; without it nothing here is precision
or recall, and `tool_id` or `hash_fields` merging more is not evidence they are better.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

from core.dedup.change import Candidate, plan_change
from core.dedup.strategies import RECOMMENDED
from core.imports.parsers import get_parser, run_parser_on_bytes
from core.imports.prepare import prepare

ROOT = Path(__file__).resolve().parent.parent
DD = ROOT / "tests/golden/ingest/defectdojo"
CASES = [  # (parser, file, label)
    ("nessus", DD / "nessus/nessus_many_vuln.xml", "Nessus sample (XML)"),
    ("nessus", DD / "nessus/nessus_many_vuln2-default.csv", "Nessus Pro (CSV)"),
    ("zap", DD / "zap/zap-results-first-scan.xml", "ZAP, bodgeit scan"),
    ("zap", DD / "zap/juicy2.xml", "ZAP, Juice Shop"),
    ("burp", DD / "burp/seven_findings.xml", "Burp"),
    ("openvas", DD / "openvas/many_vuln.xml", "OpenVAS"),
    ("nuclei", DD / "nuclei/many_findings.json", "Nuclei"),
    ("trivy", DD / "trivy/scheme_2_many_vulns.json", "Trivy"),
    ("snyk", DD / "snyk/all-projects_many_vulns.json", "Snyk"),
    ("grype", DD / "grype/many_vulns3.json", "Grype"),
    ("gitlab", DD / "gitlab/gitlab_sast--gl-sast-report-many-vuln_v15.json", "GitLab SAST"),
    ("sarif", ROOT / "tests/golden/semgrep/raw.json", "Semgrep SARIF (this project's golden)"),
]
STRATEGIES = [("tool_id", ()), ("hash_fields", ("title", "path")), ("hash_fields", ("title",))]


def measure(parser: str, path: Path) -> dict:
    if not path.is_file():
        return {"missing": True}
    res = run_parser_on_bytes(get_parser(parser), path.read_bytes())
    if not res.complete:
        return {"error": res.error}
    findings = prepare(res.findings)
    groups = defaultdict(list)
    for i, f in enumerate(findings):
        groups[f.fingerprint].append((i, f))
    cands = [
        Candidate(f"i{n}", __import__("datetime").datetime(2026, 1, 1), fp, tuple(occ))
        for n, (fp, occ) in enumerate(groups.items())
    ]
    row: dict = {"findings": len(findings), "issues_default": len(cands), "strategies": {}}
    for strategy, fields in STRATEGIES:
        plan = plan_change(cands, strategy, fields)
        label = strategy + (f"({','.join(fields)})" if fields else "")
        row["strategies"][label] = {
            "issues_after": plan.issues_after,
            "merged_away": plan.merged_away,
            "merge_groups": plan.merge_groups,
            "split": plan.issues_split,
            "new_from_split": plan.created_by_split,
        }
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    rows = []
    for parser, path, label in CASES:
        r = {"parser": parser, "label": label, **measure(parser, path)}
        rows.append(r)
        if "strategies" in r:
            cells = " | ".join(f"{k}: {v['issues_after']}" for k, v in r["strategies"].items())
            print(
                f"{label:42} findings {r['findings']:5} default {r['issues_default']:5} | {cells}"
            )
    if args.out:
        args.out.write_text(
            json.dumps(
                {"date": time.strftime("%Y-%m-%d"), "recommended": RECOMMENDED, "rows": rows},
                indent=1,
            )
            + "\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
