#!/usr/bin/env python3
"""The blind review of VEX proposals (plan §60: "100 proposals reviewed blind"; share of proposed
`vulnerable_code_not_in_execute_path` claims a reviewer confirms, and wrong claims found).

    # 1. Make the sheet: every use Bulwark proposed VEX for, mixed with as many uses it did not
    #    (it found the code using it, or could not tell), shuffled, with the tool's answer hidden.
    python scripts/vex-review-kit.py make --org ORG --out review/ [--proposals 100]
        [--controls 25] [--seed 69] [--sources projects.json]

    # 2. A reviewer who has not seen Bulwark's answers fills in review/sheet.csv: for each row,
    #    does the project's code execute the vulnerable code? yes / no / unsure.

    # 3. Score it against the hidden key.
    python scripts/vex-review-kit.py score review/

`make` reads the database in BULWARK_DATABASE_URL as the organization ORG (under RLS on Postgres).
The sheet gives the reviewer what they need and nothing of Bulwark's verdict: the project, its
repository (with `--sources`, a link to the exact tagged source: {asset id: {"repo": "owner/name",
"tag": "v1.2.3"}}), the package and version, the vulnerability, the vulnerable functions the
advisory names, and the advisory's own text. Rows are sorted by project and package -- which says
nothing about the verdict -- so a reviewer reads each project's code once.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIELDS = ["item", "project", "repository", "package", "version", "vulnerability",
          "vulnerable_functions", "advisory_summary", "executed (yes/no/unsure)", "reviewer_notes"]  # fmt: skip  # noqa: E501


def make(
    org: str, out: Path, proposals: int, seed: int, controls_n: int, sources: Path | None
) -> int:
    from sqlalchemy import select

    from core.persistence.db import get_session_factory
    from core.persistence.models import Advisory, AdvisoryImpact, Asset
    from core.tenancy import set_session_org
    from core.vex.evidence import go_imports
    from core.vex.service import uses

    rng = random.Random(seed)
    with get_session_factory()() as s:
        set_session_org(s, org)
        keys = sorted(set(s.scalars(select(AdvisoryImpact.vuln_key).where(
            AdvisoryImpact.org_id == org, AdvisoryImpact.resolved_at.is_(None)))))  # fmt: skip
        proposed, other = [], []
        for key in keys:
            for u in uses(s, org, key):
                (proposed if u.assessment.proposable else other).append((key, u))
        picked = rng.sample(proposed, min(proposals, len(proposed)))
        controls = rng.sample(other, min(controls_n, len(other)))
        links = json.loads(sources.read_text()) if sources else {}
        rows, answer = [], {}
        items = [(k, u, True) for k, u in picked] + [(k, u, False) for k, u in controls]
        rng.shuffle(items)
        labels = {
            u.impact.asset_id: (s.get(Asset, u.impact.asset_id).label or "") for _k, u, _p in items
        }  # noqa: E501
        items.sort(key=lambda i: (labels[i[1].impact.asset_id], i[1].library.name, i[0]))
        for n, (key, u, was_proposed) in enumerate(items, 1):
            asset = s.get(Asset, u.impact.asset_id)
            src = links.get(u.impact.asset_id)
            rep = s.scalars(select(Advisory).where(Advisory.id.in_(u.impact.advisory_ids))).first()
            funcs = (
                go_imports(s, u.library, u.impact.advisory_ids)
                if u.library.ecosystem == "go"
                else None
            )  # noqa: E501
            rows.append({
                "item": n, "project": asset.label if asset else "",
                "repository": f"https://github.com/{src['repo']}/tree/{src['tag']}" if src else (asset.key if asset else ""),
                "package": u.library.name, "version": u.impact.version, "vulnerability": key,
                "vulnerable_functions": "; ".join(f"{p}: {', '.join(f) or '(whole package)'}" for p, f in funcs) if funcs else "(not named by the advisory)",  # noqa: E501
                "advisory_summary": (rep.summary if rep else "")[:300],
                "executed (yes/no/unsure)": "", "reviewer_notes": "",
            })  # fmt: skip
            answer[str(n)] = {
                "proposed": was_proposed,
                "evidence": u.assessment.kind,
                "summary": u.assessment.summary,
            }  # noqa: E501
    out.mkdir(parents=True, exist_ok=True)
    with (out / "sheet.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    (out / "key.json").write_text(json.dumps(answer, indent=2))
    print(f"{len(picked)} proposals and {len(controls)} other uses in {out / 'sheet.csv'}; "
          f"{len(proposed)} proposable in all. Keep key.json from the reviewer.")  # fmt: skip
    return 0


def score(folder: Path) -> int:
    key = json.loads((folder / "key.json").read_text())
    with (folder / "sheet.csv").open(newline="") as f:
        sheet = {
            r["item"]: r["executed (yes/no/unsure)"].strip().lower() for r in csv.DictReader(f)
        }
    out: dict[str, dict[str, int]] = {"proposed": {}, "not proposed": {}}
    for item, k in key.items():
        said = sheet.get(item, "") or "blank"
        bucket = out["proposed" if k["proposed"] else "not proposed"]
        bucket[said] = bucket.get(said, 0) + 1
    p = out["proposed"]
    decided = p.get("no", 0) + p.get("yes", 0)
    print(json.dumps(out, indent=2))
    if decided:
        print(f"Proposals the reviewer confirmed (code not executed): {p.get('no', 0)} of {decided} "
              f"decided ({p.get('no', 0) / decided:.0%}); wrong claims (executed): {p.get('yes', 0)}; "
              f"unsure or blank: {sum(p.values()) - decided}")  # fmt: skip
    missed = out["not proposed"].get("no", 0)
    print(f"Uses not proposed that the reviewer judged not executed (missed proposals): {missed}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--org", required=True)
    m.add_argument("--out", type=Path, required=True)
    m.add_argument("--proposals", type=int, default=100)
    m.add_argument("--seed", type=int, default=69)
    m.add_argument("--controls", type=int, default=25, help="uses not proposed, mixed in")
    m.add_argument("--sources", type=Path, help="links to each project's tagged source")
    sc = sub.add_parser("score")
    sc.add_argument("folder", type=Path)
    args = ap.parse_args()
    if args.cmd == "make":
        return make(args.org, args.out, args.proposals, args.seed, args.controls, args.sources)
    return score(args.folder)


if __name__ == "__main__":
    sys.exit(main())
