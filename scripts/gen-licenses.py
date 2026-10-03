#!/usr/bin/env python3
"""Generate THIRD_PARTY_LICENSES.md and enforce the license policy.

    python scripts/gen-licenses.py            # write THIRD_PARTY_LICENSES.md
    python scripts/gen-licenses.py --check    # policy only: exit 1 on an unknown or denied license

Sources: installed Python distributions reachable from bulwark-scan's requirements (with extras), the npm
lockfiles of the web app and the VS Code extension, and a maintained table of the scanners, tools and data
sets Bulwark runs or ships. The table is checked against the adapters and Dockerfiles so a new scanner cannot
be added without a license entry. Nothing here is legal advice.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "THIRD_PARTY_LICENSES.md"

# Denied outright in anything Bulwark links or ships. Network-copyleft and source-available licenses.
DENY = re.compile(r"\b(AGPL|SSPL|BUSL|Commons-Clause|CC-BY-NC|Elastic)", re.I)
# Allowed, but each use must be explained in the report (weak copyleft).
REVIEW = re.compile(r"\b(LGPL|MPL|EPL|CDDL|GPL)", re.I)

# name -> (license, source, how Bulwark uses it). "runs" = in a container, not linked or redistributed.
TOOLS: dict[str, tuple[str, str, str]] = {
    "bandit": ("Apache-2.0", "https://github.com/PyCQA/bandit", "runs in a container"),
    "semgrep": ("LGPL-2.1-only (engine)", "https://github.com/semgrep/semgrep", "runs in a container"),
    "semgrep-rules": ("Semgrep Rules License v1.0", "https://github.com/semgrep/semgrep-rules",
                      "fetched at image build; never committed or redistributed (ADR-006)"),
    "opengrep": ("LGPL-2.1-only (engine)", "https://github.com/opengrep/opengrep",
                 "hosted mode's SAST tool (ADR-0038); runs in a container, binary pinned by sha256 "
                 "-- never bundles opengrep-rules (Commons Clause), uses docker/opengrep/rules/ "
                 "instead, originally written for this project under its own Apache-2.0 license"),
    "gitleaks": ("MIT", "https://github.com/gitleaks/gitleaks", "upstream image, runs in a container"),
    "trivy": ("Apache-2.0", "https://github.com/aquasecurity/trivy", "runs in a container"),
    "osv-scanner": ("Apache-2.0", "https://github.com/google/osv-scanner", "runs in a container"),
    "grype": ("Apache-2.0", "https://github.com/anchore/grype", "runs in a container"),
    "checkov": ("Apache-2.0", "https://github.com/bridgecrewio/checkov", "runs in a container"),
    "gosec": ("Apache-2.0", "https://github.com/securego/gosec", "runs in a container"),
    "dockle": ("Apache-2.0", "https://github.com/goodwithtech/dockle", "runs in a container"),
    "syft": ("Apache-2.0", "https://github.com/anchore/syft", "SBOM generation, runs in a container"),
    "cosign": ("Apache-2.0", "https://github.com/sigstore/cosign", "signing, runs in a container"),
    "prometheus": ("Apache-2.0", "https://github.com/prometheus/prometheus", "optional compose profile"),
    "jaeger": ("Apache-2.0", "https://github.com/jaegertracing/jaeger", "optional compose profile"),
    "grafana": ("AGPL-3.0-only", "https://github.com/grafana/grafana",
                "optional compose profile, run unmodified as a separate container; nothing links to it"),
    "postgres": ("PostgreSQL License", "https://www.postgresql.org/", "container image"),
    "pgvector": ("PostgreSQL License", "https://github.com/pgvector/pgvector", "built into the database image"),
    "redis": ("BSD-3-Clause (pinned to 7.2)", "https://github.com/redis/redis",
              "container image; 7.4 and later are RSALv2/SSPLv1, so the tag is pinned (ADR-0011)"),
    "rustfs": ("Apache-2.0", "https://github.com/rustfs/rustfs", "container image (object store)"),
    "egress-sidecar": ("GPL-2.0-only (nftables)", "https://git.netfilter.org/nftables/",
                        "Bulwark's own image (docker/egress-sidecar, Week 46 §22.1); runs nftables "
                        "as a separate container process to police another container's network "
                        "namespace, never linked into Bulwark's own code"),
    "dast-egress-proxy": ("Apache-2.0 (Bulwark's own code)", "https://www.python.org/",
                          "Bulwark's own image (docker/dast-egress-proxy, Week 49 §22.4): a pure-"
                          "stdlib asyncio allow-list proxy, no third-party packages installed"),
    "ingest-parser": ("Apache-2.0 (Bulwark's own code; ijson BSD-3-Clause/ISC, google-re2 "
                      "BSD-3-Clause, defusedxml PSF-2.0)", "https://pypi.org/project/ijson/",
                      "Bulwark's own image (docker/ingest-parser, Week 54 §42.2): parses uploaded "
                      "reports inside the scanner sandbox. Three permissive Python libraries, "
                      "pip-installed into the image: ijson (streaming JSON), google-re2 (linear-"
                      "time regular expressions) and defusedxml (XML without entity expansion)"),
}  # fmt: skip
DATA: list[tuple[str, str, str]] = [
    (
        "OWASP Benchmark v1.2beta",
        "GPL-2.0",
        "benchmark input, downloaded at run time only, never committed or redistributed",
    ),
    (
        "Juliet Test Suite for Java 1.3 (NIST SARD)",
        "public domain (NIST SARD terms)",
        "benchmark input, downloaded at run time only, never committed or redistributed",
    ),
    (
        "CWE",
        "MITRE CWE Terms of Use",
        "reference text in core/rag/corpus (attribution in NOTICE.md)",
    ),
    (
        "OWASP Cheat Sheet Series",
        "CC BY-SA 4.0",
        "adapted chunks in core/rag/corpus; share-alike applies to those files",
    ),
    (
        "EPSS scores",
        "FIRST.org, free to use with attribution",
        "downloaded at run time, never redistributed",
    ),
    ("CISA KEV catalog", "US Government work, public", "downloaded at run time"),
    ("CycloneDX 1.6 JSON schema", "Apache-2.0", "test fixture (tests/fixtures/cyclonedx)"),
    ("SARIF 2.1.0 JSON schema", "OASIS", "test fixture (tests/fixtures)"),
]


def norm_license(meta: metadata.PackageMetadata) -> str:
    """Best license string a Python distribution offers, or 'UNKNOWN'."""
    expr = (meta.get("License-Expression") or "").strip()
    if expr:
        return expr
    lic = (meta.get("License") or "").strip()
    if lic and len(lic) < 80 and "\n" not in lic:
        return lic
    classes = [
        c.split("::")[-1].strip()
        for c in meta.get_all("Classifier") or []
        if c.startswith("License ::")
    ]
    classes = [c for c in classes if c not in ("OSI Approved",)]
    return " OR ".join(dict.fromkeys(classes)) or "UNKNOWN"


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?")
SHIPPED_EXTRAS = {"llm", "otel"}  # installed in the application image; "dev" is not shipped


def _requirements(dist: metadata.Distribution, extras: set[str]) -> list[tuple[str, set[str]]]:
    """(name, extras) of what `dist` needs: the unconditional requirements plus those of the wanted extras."""
    out = []
    for req in dist.requires or []:
        m = re.search(r"extra\s*==\s*['\"]([^'\"]+)['\"]", req)
        if m and m.group(1) not in extras:
            continue
        head = _REQ.match(req)
        if head:
            out.append(
                (head.group(1), {e.strip() for e in (head.group(2) or "").split(",") if e.strip()})
            )
    return out


def python_closure(root_name: str = "bulwark-scan") -> dict[str, tuple[str, str]]:
    """{name: (version, license)} for what the application image installs: bulwark-scan's requirements,
    the extras in SHIPPED_EXTRAS, and everything they need (including the extras they ask for), as installed here.
    """
    seen: dict[str, tuple[str, str]] = {}
    todo = _requirements(metadata.distribution(root_name), SHIPPED_EXTRAS)
    done: set[tuple[str, frozenset[str]]] = set()
    while todo:
        name, extras = todo.pop()
        key = re.sub(r"[-_.]+", "-", name).lower()
        if key == root_name or (key, frozenset(extras)) in done:
            continue
        done.add((key, frozenset(extras)))
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue  # a platform-specific or optional requirement that is not installed here
        seen[key] = (dist.version, norm_license(dist.metadata))
        todo.extend(_requirements(dist, extras))
    return dict(sorted(seen.items()))


# Packages whose own package.json omits "license" (so package-lock.json has nothing to read),
# verified by hand against the package's actual LICENSE file in node_modules -- npm's own metadata
# gap, not an unknown or ambiguous license.
NPM_LICENSE_OVERRIDES: dict[str, str] = {
    # mermaid's color-math dependency (Week 45 threat-model draft); verified MIT text in
    # node_modules/khroma/license, just never added to its package.json.
    "khroma": "MIT",
}


def npm_packages(lock: Path) -> list[tuple[str, str, str, bool]]:
    """[(name, version, license, dev)] from a package-lock.json (v2/v3)."""
    out = []
    for path, p in json.loads(lock.read_text())["packages"].items():
        if not path:
            continue
        name = p.get("name") or path.rsplit("node_modules/", 1)[-1]
        lic = p.get("license")
        lic = lic if isinstance(lic, str) else ("UNKNOWN" if not lic else str(lic))
        if lic == "UNKNOWN" and name in NPM_LICENSE_OVERRIDES:
            lic = NPM_LICENSE_OVERRIDES[name]
        out.append((name, p.get("version", ""), lic, bool(p.get("dev") or p.get("devOptional"))))
    return sorted(set(out))


def policy_problems(
    py: dict[str, tuple[str, str]], npm: dict[str, list[tuple[str, str, str, bool]]]
) -> list[str]:
    problems = []
    for name, (ver, lic) in py.items():
        if lic == "UNKNOWN":
            problems.append(f"python {name} {ver}: license could not be determined")
        elif DENY.search(lic):
            problems.append(f"python {name} {ver}: denied license {lic}")
    for site, pkgs in npm.items():
        for name, ver, lic, dev in pkgs:
            if lic == "UNKNOWN":
                problems.append(f"npm ({site}) {name} {ver}: license could not be determined")
            elif DENY.search(lic) and not dev:
                problems.append(f"npm ({site}) {name} {ver}: denied license {lic}")
    return problems


def coverage_problems() -> list[str]:
    """Every scanner adapter and every image the repository builds needs an entry in TOOLS."""
    sys.path.insert(0, str(ROOT))
    from core.scan import ADAPTERS

    problems = [f"scanner {n} has no entry in TOOLS" for n in ADAPTERS if n not in TOOLS]
    for d in (ROOT / "docker").iterdir():
        if d.is_dir() and d.name not in TOOLS and d.name not in ("app", "postgres"):
            problems.append(f"docker/{d.name} has no entry in TOOLS")
    return problems


def render(py: dict[str, tuple[str, str]], npm: dict[str, list[tuple[str, str, str, bool]]]) -> str:
    L = ["# Third-party licenses", "",
         "Generated by `scripts/gen-licenses.py`; do not edit by hand. Bulwark itself is Apache-2.0. This is an",
         "inventory, not legal advice: check licenses that matter to you at the source.", "",
         "## Scanners and services (run in containers, not linked)", "",
         "| Tool | License | Source | Use |", "|---|---|---|---|"]  # fmt: skip
    for n, (lic, src, use) in sorted(TOOLS.items()):
        L.append(f"| {n} | {lic} | <{src}> | {use} |")
    L += ["", "The scanners are separate programs executed in sandboxed containers; Bulwark neither links to nor",
          "redistributes them. **Semgrep's community rules** (Semgrep Rules License v1.0) are fetched at image build",
          "and are not part of this repository (ADR-006). **Grafana** is AGPL-3.0 and only used, unmodified, as an",
          "optional separate container.", "", "## Data sets and reference text", "",
          "| Data | License / terms | Use |", "|---|---|---|"]  # fmt: skip
    L += [f"| {a} | {b} | {c} |" for a, b, c in DATA]
    L += [
        "",
        f"## Python dependencies ({len(py)})",
        "",
        "| Package | Version | License |",
        "|---|---|---|",
    ]
    L += [f"| {n} | {v} | {lic} |" for n, (v, lic) in py.items()]
    review = [(n, lic) for n, (_, lic) in py.items() if REVIEW.search(lic)]
    for site, pkgs in npm.items():
        prod = [p for p in pkgs if not p[3]]
        counts = Counter(p[2] for p in prod)
        L += ["", f"## npm dependencies: {site} ({len(prod)} runtime, {len(pkgs) - len(prod)} development)", "",
              "Runtime license summary: " + ", ".join(f"{k} {v}" for k, v in counts.most_common()), "",
              "| Package | Version | License |", "|---|---|---|"]  # fmt: skip
        L += [f"| {n} | {v} | {lic} |" for n, v, lic, _ in prod]
        review += [(n, lic) for n, _, lic, _ in prod if REVIEW.search(lic)]
    if review:
        L += ["", "## Weak-copyleft licenses in the dependency tree", "",
              "Allowed, listed so the obligations are visible (dynamic linking or use as an unmodified library):", ""]  # fmt: skip
        L += [f"- {n}: {lic}" for n, lic in sorted(set(review))]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="policy check only; write nothing")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    py = python_closure()
    npm = {
        "web app": npm_packages(ROOT / "web" / "package-lock.json"),
        "VS Code extension": npm_packages(ROOT / "extensions" / "vscode" / "package-lock.json"),
    }
    problems = policy_problems(py, npm) + coverage_problems()
    for p in problems:
        print("license policy:", p, file=sys.stderr)
    if not args.check:
        args.out.write_text(render(py, npm))
        print(
            f"wrote {args.out} ({len(py)} python, {sum(len(v) for v in npm.values())} npm packages)"
        )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
