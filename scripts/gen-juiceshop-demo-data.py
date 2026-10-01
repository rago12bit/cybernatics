#!/usr/bin/env python3
"""Converts a real `bulwark scan --format json` run of OWASP Juice Shop into
web/lib/juiceshop-demo-data.json -- the data the public landing page's live-scan replay
(web/components/LiveJuiceShopDemo.tsx) is built from (Week 52 task 2, plan §33).

Reproduce the source scan with:

    bulwark scan https://github.com/juice-shop/juice-shop --format json --output juiceshop-raw.json
    python scripts/gen-juiceshop-demo-data.py juiceshop-raw.json

This is a real scan of the real, public OWASP Juice Shop repository -- every finding, every tool
duration, and every severity count in the output is what Bulwark actually reported, not fabricated
or hand-tuned for a better-looking demo. The only synthetic fields are the scan id and timestamps
(a public demo scan has no real database row).
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "web" / "lib" / "juiceshop-demo-data.json"


def convert_tool_status(raw: dict[str, dict]) -> dict[str, dict]:
    out = {}
    for name, t in raw.items():
        status = t["status"]
        out[name] = {
            "status": status,
            "findings": t.get("findings", 0),
            "exit_code": t.get("exit_code"),
            "duration_seconds": t.get("duration_seconds"),
            "error": t.get("reason") or t.get("error"),
            "warnings": t.get("warnings"),
            # Never ship raw scanner output from a public demo: some of these findings are
            # Gitleaks hits, and withholding the raw artifact is this project's own standing rule
            # for any scan where secrets were found (see api/schemas.py's same "withheld" value).
            "raw_artifact": "withheld",
        }
    return out


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <raw-scan.json>", file=sys.stderr)
        raise SystemExit(2)
    raw = json.loads(Path(sys.argv[1]).read_text())
    findings = raw["findings"]
    severity_counts = dict(Counter(f["scoring"]["normalized_severity"] for f in findings))
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    doc = {
        "scan": {
            "id": "00000000-0000-0000-0000-00000000j51c",
            "status": "completed",
            "source_type": "git",
            "source_label": "github.com/juice-shop/juice-shop",
            "tools": list(raw["tool_status"]),
            "created_at": now,
            "started_at": now,
            "finished_at": now,
            "error": None,
            "tool_status": convert_tool_status(raw["tool_status"]),
            "severity_counts": severity_counts,
            "raw_findings": raw["stats"]["raw_findings"],
            "unique_findings": raw["stats"]["unique_findings"],
            "dedup_rate": raw["stats"]["dedup_rate"],
        },
        "findings": findings,
        "risk_feeds": {"epss_date": None, "kev_version": None},
    }
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {OUT} ({len(findings)} findings)")


if __name__ == "__main__":
    main()
