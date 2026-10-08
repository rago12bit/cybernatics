#!/usr/bin/env python3
"""Prepare a Bulwark instance for the third usability study (Week 74, docs/ux-study-v3-protocol.md).

Through the public API only, so it works against the throwaway `scripts/e2e_server.py` the protocol
uses or against a real deployment:

  - three projects: payments-api (with the AWS key finding J8 accepts), storefront (J9's pen test)
    and billing-service;
  - billing-service's SBOM with log4j-core 2.14.1, and payments-api's with the fixed 2.17.1, so J7
    has one affected project and one that is not;
  - GitHub ticket settings for billing-service, so J7 files a ticket;
  - in `--out`: the Nessus export J6 imports, and J9's five findings as a printed list.

    python scripts/ux-study-seed.py                       # the e2e server on localhost:8800
    BULWARK_TOKEN=... python scripts/ux-study-seed.py --api https://bulwark.example.com

Run it once per participant, on a fresh instance: every participant must start from the same data.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
E2E_TOKEN = "e2e-test-token-not-a-real-secret-0123456789"  # scripts/e2e_server.py's; fake
E2E_APPROVER = "bulwark_e2e0approver0not0a0real0secret0000000000_0XGUOc"  # its "Priya N."; fake
NESSUS = ROOT / "tests/golden/ingest/defectdojo/nessus/nessus_many_vuln2-default.csv"
J9_FINDINGS = """\
Five findings from the storefront pen test (J9). Record each one.

1. IDOR on order history -- GET /v2/orders/{id} returns another customer's order.
   CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
2. Stored XSS in product reviews -- POST /v2/reviews keeps <script> in the review body.
   CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N
3. Password reset token never expires -- POST /v2/password-reset.
   CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
4. Verbose stack traces on 500 -- POST /v2/checkout with an empty cart.
   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
5. No rate limit on login -- POST /v2/login accepts 1,000 attempts a minute.
   CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N
"""


class Api:
    def __init__(self, base: str, token: str) -> None:
        self.c = httpx.Client(
            base_url=base, headers={"Authorization": f"Bearer {token}"}, timeout=60
        )

    def call(self, method: str, path: str, **kw: Any) -> Any:
        r = self.c.request(method, path, **kw)
        if r.status_code >= 400:
            sys.exit(f"{method} {path}: HTTP {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else None

    def project(self, url: str) -> str:
        scan = self.call("POST", "/scans", json={"source": {"type": "git", "url": url}})
        for _ in range(120):
            if self.call("GET", f"/scans/{scan['id']}")["status"] in (
                "completed",
                "partial",
                "failed",
            ):
                break
            time.sleep(1)
        return next(a["id"] for a in self.call("GET", "/assets") if a["label"] == url)

    def sbom(self, project: str, version: str) -> None:
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": [{
            "type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core",
            "version": version, "purl": f"pkg:maven/org.apache.logging.log4j/log4j-core@{version}"}]}  # fmt: skip
        r = self.call("POST", "/v2/ingest", data={"project": project},
                      files={"file": ("sbom.cdx.json", json.dumps(doc).encode())})  # fmt: skip
        for _ in range(60):
            if self.call("GET", f"/v2/imports/{r['import_id']}")["status"] not in (
                "queued",
                "processing",
            ):
                return
            time.sleep(0.5)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    # Not 8000: a developer's own Bulwark (docker compose) usually has it, and seeding that by
    # mistake would write the study's scenario into their real data.
    ap.add_argument("--api", default="http://localhost:8800")
    ap.add_argument("--out", default="ux-study-files", help="where to put J6's file and J9's list")
    args = ap.parse_args()
    e2e = args.api.rstrip("/") in ("http://localhost:8800", "http://127.0.0.1:8800")
    token = os.environ.get("BULWARK_TOKEN") or (E2E_TOKEN if e2e else "")
    if not token:
        sys.exit("set BULWARK_TOKEN to a token that may scan, import and change settings")
    api = Api(args.api, token)

    payments = api.project("https://github.com/acme/payments-api")
    api.project("https://github.com/acme/storefront")
    billing = api.project("https://github.com/acme/billing-service")
    api.sbom(billing, "2.14.1")  # affected by CVE-2021-44228
    api.sbom(payments, "2.17.1")  # fixed: J7 should see it is not affected
    api.call("PUT", "/settings/integrations", json={
        "github_token": "ux-study-fake-token-not-a-secret", "github_issues_repo": "acme/security"})  # fmt: skip
    api.call(
        "PUT",
        f"/v2/projects/{billing}/tickets",
        json={"provider": "github", "target": "acme/security"},
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(NESSUS, out / "nessus-external-q4.csv")
    (out / "j9-pentest-findings.txt").write_text(J9_FINDINGS)

    print(f"Seeded {args.api}: payments-api, storefront, billing-service.")
    print(f"J6 file: {(out / 'nessus-external-q4.csv').resolve()}")
    print(f"J9 list: {(out / 'j9-pentest-findings.txt').resolve()}")
    if e2e:
        print("Participant signs in with 'Use an API token instead':")
        print(f"  {E2E_TOKEN}")
        print("J8's approver (Priya N.) signs in, in a second browser window, with:")
        print(f"  {E2E_APPROVER}")
    else:
        print("J8 needs a second person: make the approver a personal token on this instance.")


if __name__ == "__main__":
    main()
