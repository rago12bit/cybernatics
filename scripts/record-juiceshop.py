#!/usr/bin/env python3
"""Record the public site's Juice Shop scan (Week 77, plan §57 "Home with the recorded Juice Shop
scan"): one release of OWASP Juice Shop, scanned two ways by Bulwark's own code, written to
web/lib/juiceshop-demo-data.json for the home page and /sample.

* **Code**: the release's source, by the default scanners (`core.scan.scan`, what `bulwark scan`
  runs).
* **Running app**: the same release's container, by a passive DAST campaign's tools
  (`core.dast.campaign.TOOLS_FOR_MODE["passive"]`: ZAP baseline) behind the campaign's own egress
  proxy (`core.dast.proxy.BackgroundProxy`), allowed to reach the target host and nothing else.
  Egress the proxy refused is recorded, not hidden.

Reproduce (the Juice Shop container must not be reachable from anywhere but this machine):

    git clone --depth 1 --branch v17.3.0 https://github.com/juice-shop/juice-shop.git /tmp/js
    docker run -d --name juiceshop -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v17.3.0
    python scripts/record-juiceshop.py --source /tmp/js --image bkimminich/juice-shop:v17.3.0

What is *not* the product's own path, said here so the page can say it too: a real campaign first
re-verifies that the organization owns the target (DNS TXT or a well-known file) and stores its
results; a container on localhost has no domain to verify, so this script calls the campaign's tools
directly, with the same adapters and the same proxy. The active tier (Nuclei) is not recorded: a
live run against this target timed out with nothing kept.

Every count, finding, duration and refused connection in the output is what those runs reported.
The only synthetic fields are the scan ids and the timestamps the replay restamps on load.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "web" / "lib" / "juiceshop-demo-data.json"


def tool_view(t: dict[str, Any], *, withheld: bool) -> dict[str, Any]:
    return {
        "status": t["status"],
        "findings": t.get("findings", 0),
        "exit_code": t.get("exit_code"),
        "duration_seconds": t.get("duration_seconds"),
        "error": t.get("reason") or t.get("error"),
        "warnings": t.get("warnings"),
        # The product's rule (api/schemas.py): a scan that found secrets withholds its raw output, and
        # the page says why. A scan that found none has no raw output here either (a public page
        # ships none), but must not claim secrets as the reason.
        "raw_artifact": "withheld" if withheld else None,
    }


def scan_view(
    scan_id: str,
    label: str,
    source_type: str,
    tools: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
    raw: int,
    unique: int,
    now: str,
) -> dict[str, Any]:
    secrets = any(f["taxonomy"]["category"] == "secrets" for f in findings)
    return {
        "id": scan_id,
        "status": "completed",
        "source_type": source_type,
        "source_label": label,
        "tools": list(tools),
        "created_at": now,
        "started_at": now,
        "finished_at": now,
        "error": None,
        "tool_status": {n: tool_view(t, withheld=secrets) for n, t in tools.items()},
        "severity_counts": dict(Counter(f["scoring"]["normalized_severity"] for f in findings)),
        "raw_findings": raw,
        "unique_findings": unique,
        "dedup_rate": round(1 - unique / raw, 3) if raw else 0.0,
    }


def record_code(source: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], int, int]:
    from core.scan import DEFAULT_TOOLS, scan

    result = scan(source, list(DEFAULT_TOOLS))
    return (
        result.tool_status,
        [f.to_dict() for f in result.findings],
        result.stats.raw,
        result.stats.unique,
    )


def record_runtime(
    target: str,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], int, int, list[dict[str, Any]]]:
    from core.correlation import correlate
    from core.dast.adapters.zap import ZapError, run_zap_baseline
    from core.dast.campaign import TOOLS_FOR_MODE
    from core.dast.proxy import BackgroundProxy, ProxyConfig
    from core.postprocess import finalize

    assert TOOLS_FOR_MODE["passive"] == ("zap-baseline",), "the passive tier changed; update this"
    blocked: list[dict[str, Any]] = []
    host = urlsplit(target).hostname or target

    def on_blocked(h: str, port: int, is_connect: bool) -> None:
        blocked.append({"host": h, "port": port, "protocol": "https" if is_connect else "http"})

    tools: dict[str, dict[str, Any]] = {}
    found = []
    with BackgroundProxy(frozenset({host}), on_blocked=on_blocked) as proxy:
        started = time.monotonic()
        try:
            found = run_zap_baseline(
                target, proxy=ProxyConfig(host="host.docker.internal", port=proxy.port)
            )
            status: dict[str, Any] = {"status": "ok", "findings": len(found)}
        except ZapError as exc:
            status = {"status": "error", "error": str(exc)}
        status["duration_seconds"] = round(time.monotonic() - started, 2)
        tools["zap-baseline"] = status
    correlated, stats = correlate(found)
    final = finalize(correlated)
    refused = Counter((b["host"], b["port"], b["protocol"]) for b in blocked)
    egress = [
        {"host": h, "port": p, "protocol": proto, "attempts": n}
        for (h, p, proto), n in refused.most_common()
    ]
    return tools, [f.to_dict() for f in final], stats.raw, stats.unique, egress


def image_digest(image: str) -> str:
    out = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True, help="a checkout of the release")
    ap.add_argument(
        "--image", required=True, help="the running container's image, e.g. ...:v17.3.0"
    )
    ap.add_argument("--target", default="http://localhost:3000")
    args = ap.parse_args()

    version = args.image.rsplit(":", 1)[-1]
    commit = subprocess.run(
        ["git", "-C", str(args.source), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    bulwark = next(
        line.split('"')[1]
        for line in (ROOT / "pyproject.toml").read_text().splitlines()
        if line.startswith("version = ")
    )

    code_tools, code_findings, code_raw, code_unique = record_code(args.source)
    rt_tools, rt_findings, rt_raw, rt_unique, egress = record_runtime(args.target)

    doc = {
        "provenance": {
            "app": "OWASP Juice Shop",
            "version": version,
            "commit": commit,
            "image": image_digest(args.image),
            "recorded_on": now[:10],
            "bulwark_version": bulwark,
            "made_by": "scripts/record-juiceshop.py",
        },
        "scan": scan_view(
            "00000000-0000-0000-0000-0000000js177",
            f"juice-shop {version} (source)",
            "git",
            code_tools,
            code_findings,
            code_raw,
            code_unique,
            now,
        ),
        "findings": code_findings,
        "runtime": {
            "scan": scan_view(
                "00000000-0000-0000-0000-0000000js277",
                f"juice-shop {version} (running)",
                "web",
                rt_tools,
                rt_findings,
                rt_raw,
                rt_unique,
                now,
            ),
            "findings": rt_findings,
            "mode": "passive",
            "refused_egress": egress,
        },
        "risk_feeds": {"epss_date": None, "kev_version": None},
    }
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print(
        f"wrote {OUT}: code {code_raw} raw -> {code_unique}; running app {rt_raw} raw -> "
        f"{rt_unique}; {sum(e['attempts'] for e in egress)} refused connections"
    )


if __name__ == "__main__":
    main()
