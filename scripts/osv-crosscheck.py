#!/usr/bin/env python3
"""Bulwark's advisory matching against osv-scanner's, on the same SBOMs and the same OSV data (plan
§46.2: "Getting range matching right is the hard part; test it against osv-scanner on the same
SBOMs").

For each ecosystem it samples advisories from an OSV dump, takes versions at and around each
range's boundaries (every `introduced`, `fixed` and `last_affected` version, and some listed
affected versions) -- where range matching goes wrong -- writes them as one CycloneDX SBOM, runs
osv-scanner on it fully offline against the *same* zip, and compares, package by package, which
advisories each says apply. Every disagreement is written out.

    python scripts/osv-crosscheck.py --zips DIR --cache DIR --out report.json

DIR holds `<Ecosystem>-all.zip`; the cache dir holds the same files as osv-scanner expects them
(`osv-scalibr/<Ecosystem>/all.zip`, hard links), so neither tool downloads anything.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.advisories.osv import ECOSYSTEMS, Advisory, affects, parse  # noqa: E402
from core.inventory.identity import library_key  # noqa: E402


def purl(eco: str, name: str, version: str) -> str:
    if eco == "maven":
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{quote(group)}/{quote(artifact)}@{quote(version)}"
    if eco == "go":
        v = version if version.startswith("v") else f"v{version}"
        return f"pkg:golang/{name}@{quote(v)}"
    if eco == "npm":
        return (
            "pkg:npm/" + "/".join(quote(p, safe="") for p in name.split("/")) + f"@{quote(version)}"
        )
    return f"pkg:pypi/{quote(name)}@{quote(version)}"


def load(zip_path: Path) -> list[Advisory]:
    out = []
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            a = parse(z.read(n))
            if a is not None:
                out.append(a)
    return out


def candidates(rng: random.Random, advisories: list[Advisory], eco: str, packages: int) -> set[tuple[str, str]]:  # fmt: skip
    by_pkg: dict[str, list[tuple[str, set[str]]]] = defaultdict(list)
    for a in advisories:
        for af in a.affected:
            if af.ecosystem != eco:
                continue
            versions = {v for r in af.ranges if r.type in ("SEMVER", "ECOSYSTEM")
                        for k, v in r.events if k != "limit" and v != "0"}  # fmt: skip
            versions |= set(rng.sample(af.versions, min(3, len(af.versions))))
            by_pkg[af.name].append((a.id, versions))
    # Packages with a version boundary to test: most npm records are malicious-package reports
    # affecting every version (`introduced: "0"` and nothing else), which would crowd them out.
    testable = sorted(n for n, entries in by_pkg.items() if any(vs for _id, vs in entries))
    names = rng.sample(testable, min(packages, len(testable)))
    out = set()
    for name in names:
        for _id, versions in by_pkg[name]:
            for v in versions:
                if v and len(v) < 100 and not any(c.isspace() for c in v):
                    out.add((name, v))
    return out


def bulwark(index: dict[str, list[Advisory]], eco: str, name: str, version: str) -> tuple[set[str], set[str]]:  # fmt: skip
    hits, unknown = set(), set()
    for a in index.get(library_key(eco, name), []):
        if a.withdrawn is not None:
            continue
        results = [affects(af, version) for af in a.affected if af.library_key == library_key(eco, name)]  # fmt: skip
        if any(r is True for r in results):
            hits.add(a.id)
        elif any(r is None for r in results):
            unknown.add(a.id)
    return hits, unknown


class Database:
    """The same comparison through Bulwark's real path: the dumps ingested by `feeds.update_osv`,
    each SBOM recorded as a project's inventory (which runs matching), the stored impacts read
    back -- so the matcher's database side is checked too, not only `affects()`."""

    def __init__(self, url: str, zips: Path) -> None:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from core.advisories import feeds
        from core.persistence.models import Base, Organization

        engine = create_engine(url)
        Base.metadata.create_all(engine)
        self.sessions = sessionmaker(engine, expire_on_commit=False)
        self.org = "xcheck"
        with self.sessions() as s:
            if s.get(Organization, self.org) is None:
                s.add(Organization(id=self.org, name="cross-check"))
                s.commit()
            for osv_eco in ECOSYSTEMS:
                feeds.update_osv(s, osv_eco, zip_path=zips / f"{osv_eco}-all.zip")

    def matches(self, eco: str, comps: list[tuple[str, str]]) -> dict[tuple[str, str], set[str]]:
        from sqlalchemy import select

        from core import inventory
        from core.persistence import repo
        from core.persistence.models import AdvisoryImpact, Library

        with self.sessions() as s:
            sc = repo.create_scan(s, source_type="git", source_ref=f"https://example.com/{eco}",
                                  source_label=f"xcheck/{eco}", tools=["syft"], org_id=self.org)  # fmt: skip
            assert sc.asset_id is not None
            inventory.record(s, org_id=self.org, asset_id=sc.asset_id, scan_id=sc.id, source="scan",
                             packages=[{"purl": purl(eco, n, v)} for n, v in comps])  # fmt: skip
            out: dict[tuple[str, str], set[str]] = defaultdict(set)
            for name, version, ids in s.execute(
                select(Library.name, AdvisoryImpact.version, AdvisoryImpact.advisory_ids)
                .join(Library, Library.id == AdvisoryImpact.library_id)
                .where(AdvisoryImpact.asset_id == sc.asset_id, AdvisoryImpact.certain.is_(True),
                       AdvisoryImpact.resolved_at.is_(None))
            ):  # fmt: skip
                out[(name, version)] |= set(ids)
            return out


def osv_scanner(binary: str, cache: Path, sbom: Path) -> dict[tuple[str, str], set[str]]:
    env = {**os.environ, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache)}
    run = subprocess.run(
        [binary, "scan", "source", "--offline", "--offline-vulnerabilities", "-L", str(sbom),
         "--format", "json"],
        capture_output=True, env=env, timeout=1800, check=False,
    )  # fmt: skip
    if run.returncode not in (0, 1):
        raise RuntimeError(f"osv-scanner exited {run.returncode}: {run.stderr.decode()[-500:]}")
    out: dict[tuple[str, str], set[str]] = defaultdict(set)
    for res in json.loads(run.stdout).get("results") or []:
        for p in res.get("packages") or []:
            v = str(p["package"]["version"])
            out[(str(p["package"]["name"]), v)] |= {str(x["id"]) for x in p.get("vulnerabilities") or []}  # fmt: skip
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zips", type=Path, required=True)
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--packages", type=int, default=400, help="packages sampled per ecosystem")
    ap.add_argument("--seed", type=int, default=68)
    ap.add_argument("--osv-scanner", default=str(Path.home() / ".local/bin/osv-scanner"))
    ap.add_argument("--database", help="also check Bulwark's stored matches (a SQLAlchemy URL)")
    args = ap.parse_args()
    db = Database(args.database, args.zips) if args.database else None
    rng = random.Random(args.seed)
    report: dict[str, object] = {"seed": args.seed, "packages_per_ecosystem": args.packages}
    work = args.out.parent / "xcheck-sboms"
    work.mkdir(parents=True, exist_ok=True)
    for osv_eco, eco in ECOSYSTEMS.items():
        advisories = load(args.zips / f"{osv_eco}-all.zip")
        index: dict[str, list[Advisory]] = defaultdict(list)
        for a in advisories:
            for key in {af.library_key for af in a.affected}:
                index[key].append(a)
        comps = sorted(candidates(rng, advisories, eco, args.packages))
        sbom = work / f"{osv_eco}.cdx.json"
        sbom.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [{"type": "library", "bom-ref": f"c{i}", "name": n, "version": v,
                            "purl": purl(eco, n, v)} for i, (n, v) in enumerate(comps)],
        }))  # fmt: skip
        theirs = osv_scanner(args.osv_scanner, args.cache, sbom)
        stored = db.matches(eco, comps) if db else None
        db_disagree = []
        agree = 0
        disagreements = []
        unknown_total = 0
        for name, v in comps:
            mine, unknown = bulwark(index, eco, name, v)
            unknown_total += len(unknown)
            other = theirs.get((name, v if eco != "go" else f"v{v.removeprefix('v')}"), set()) | theirs.get((name, v), set())  # fmt: skip
            if stored is not None:
                kept = stored.get((name, v), set()) | stored.get((name, f"v{v.removeprefix('v')}"), set())  # fmt: skip
                if kept != mine:
                    db_disagree.append({"package": name, "version": v, "stored": sorted(kept), "evaluated": sorted(mine)})  # fmt: skip
            if mine == other:
                agree += 1
                continue
            disagreements.append({
                "package": name, "version": v,
                "only_bulwark": sorted(mine - other), "only_osv_scanner": sorted(other - mine),
                "bulwark_could_not_tell": sorted(unknown & other),
            })  # fmt: skip
        pairs_mine = sum(len(bulwark(index, eco, n, v)[0]) for n, v in comps)
        report[osv_eco] = {
            "advisories_in_dump": len(advisories),
            "components": len(comps),
            "agree": agree,
            "disagree": len(disagreements),
            "advisory_matches_bulwark": pairs_mine,
            "advisory_matches_osv_scanner": sum(len(s) for s in theirs.values()),
            "could_not_tell": unknown_total,
            "disagreements": disagreements,
            "database_disagrees_with_evaluation": db_disagree if stored is not None else None,
        }
        print(f"{osv_eco:6s} {len(comps):5d} components: {agree} agree, {len(disagreements)} disagree "
              f"({pairs_mine} matches by Bulwark, {unknown_total} could not tell)"
              + (f"; stored matches differ on {len(db_disagree)}" if stored is not None else ""), flush=True)  # fmt: skip
    args.out.write_text(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
