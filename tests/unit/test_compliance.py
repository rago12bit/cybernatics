"""Compliance and evidence (plan §47): the audit log's version-2 entries and the extract an
organization can show without revealing anyone else's; mappings as versioned data that cite their
sources; the ASVS benchmark per project, where only a person marks a requirement met; and the
evidence pack -- its SLA adherence, risk acceptances and coverage, its bundle checked by the same
standalone `verify.py` an auditor runs, its signature, and nothing of another organization."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from core import audit, compliance
from core.evidence import audit_extract, verifier
from core.models import Severity
from core.persistence import repo
from core.persistence.models import (
    AuditEntry,
    Engagement,
    EngagementChecklistItem,
    EvidencePack,
    IssueRow,
    RiskAcceptance,
)
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token
from tests.unit.test_sla import finding, put, scan

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
NOW = datetime.now(timezone.utc)


# ------------------------------------------------------------------ the audit log


def _legacy(s: Any, seq: int, prev: str) -> AuditEntry:
    """A version-1 entry, as every entry before migration 0041 is."""
    ts = NOW - timedelta(days=3)
    pd = audit.payload_digest({"legacy": seq})
    h = audit.compute_hash(seq=seq, prev_hash=prev, timestamp=ts, actor="cli:old",
                           action="token.created", target=f"t{seq}", payload_digest=pd)  # fmt: skip
    row = AuditEntry(seq=seq, prev_hash=prev, entry_hash=h, timestamp=ts, actor="cli:old",
                     action="token.created", target=f"t{seq}", payload_digest=pd, version=1)  # fmt: skip
    s.add(row)
    s.commit()
    return row


def test_an_extract_shows_one_organizations_entries_and_still_checks_every_link(env: Env) -> None:
    with env.sessions() as s:
        first = _legacy(s, 1, audit.GENESIS_HASH)
        mine = repo.append_audit_entry(s, actor="token:alice", action="issue.triage.not_a_risk",
                                       target="issue-1", payload={"reason": "x"},
                                       org_id=DEFAULT_ORG_ID)  # fmt: skip
        theirs = repo.append_audit_entry(s, actor="token:zq-other-org-actor", action="zq.other.action",
                                         target="their-thing", payload={"org_id": OTHER_ORG})  # fmt: skip
        deployment = repo.append_audit_entry(s, actor="cli:audit", action="audit.checkpointed",
                                             target="cp", payload={})  # fmt: skip
        assert (first.version, mine.version) == (1, 2)
        assert mine.org_id == DEFAULT_ORG_ID and theirs.org_id == OTHER_ORG  # from the payload
        assert deployment.org_id is None
        entries = repo.list_audit_entries(s)
        assert audit.verify_chain(entries).ok
        # A version-2 entry's organization is inside its hash: moving it to another org shows.
        entries[1].org_id = OTHER_ORG
        assert audit.verify_chain(entries).broken_at_seq == 2
        s.rollback()
        repo.record_checkpoint(s, seq_end=deployment.seq, chain_hash=deployment.entry_hash,
                               signature_bundle="{}", rekor_log_index=42)  # fmt: skip
        ex = audit_extract.extract(s, DEFAULT_ORG_ID, NOW - timedelta(days=1), NOW + timedelta(days=1))  # fmt: skip

    shown = [e for e in ex["entries"] if not e.get("withheld")]
    assert [e["actor"] for e in shown] == ["token:alice"]
    assert "zq" not in json.dumps(ex)  # another organization's entry is hashes only
    assert [e["seq"] for e in ex["entries"]] == [2, 3, 4]  # the period's entries
    check = verifier.verify_extract(ex)
    assert check["ok"] and check["recomputed"] == 3 and check["anchored_at"] == [4]
    assert check["all_disclosed_anchored"]

    # The verifier is standalone; its hashes are core.audit's.
    e = shown[0]
    assert verifier.body_digest(e) == audit.body_digest(
        timestamp=e["timestamp"], org_id=e["org_id"], actor=e["actor"], action=e["action"],
        target=e["target"], payload_digest=e["payload_digest"],
    )  # fmt: skip
    assert verifier.hash_v2(e["seq"], e["prev_hash"], e["body_digest"]) == e["entry_hash"]

    # Rewriting anything -- one's own entry, or another's link -- fails the check.
    forged = json.loads(json.dumps(ex))
    next(x for x in forged["entries"] if not x.get("withheld"))["action"] = "issue.triage.reopen"
    assert not verifier.verify_extract(forged)["ok"]
    forged = json.loads(json.dumps(ex))
    forged["entries"][1]["prev_hash"] = "f" * 64
    assert not verifier.verify_extract(forged)["ok"]
    forged = json.loads(json.dumps(ex))
    forged["checkpoints"][0]["chain_hash"] = "0" * 64
    assert "different hash" in verifier.verify_extract(forged)["problems"][0]

    # Over the legacy entry, the extract can only check its link.
    with env.sessions() as s:
        wide = audit_extract.extract(s, DEFAULT_ORG_ID, NOW - timedelta(days=5), NOW + timedelta(days=1))  # fmt: skip
    wide_check = verifier.verify_extract(wide)
    assert wide_check["ok"] and wide_check["linked_only"] == 1 and wide_check["first_seq"] == 1


# ------------------------------------------------------------------ mappings


def test_every_mapping_cites_its_source_and_maps_to_known_evidence(env: Env) -> None:
    fws = compliance.frameworks()
    assert set(fws) == {"asvs-4.0.3", "iso27001-2022-a8.8", "owasp-top10-2021",
                        "pci-dss-4.0-req6", "soc2-2017-cc7.1"}  # fmt: skip
    for fw in fws.values():
        assert fw.source["url"].startswith("https://") and fw.source["terms"]
        assert fw.mapping_version >= 1 and fw.controls
        for c in fw.controls:
            assert set(c.evidence) <= set(compliance.EVIDENCE)
    pci = {c.id: c for c in fws["pci-dss-4.0-req6"].controls}
    assert "component_inventory" in pci["6.3.2"].evidence and "CWE-89" in pci["6.2.4"].cwes
    assert len(fws["asvs-4.0.3"].controls) == 278 and len(fws["owasp-top10-2021"].controls) == 10
    assert "not reproduced" in fws["iso27001-2022-a8.8"].source["terms"]

    r = env.client.get("/v2/compliance/frameworks", headers=AUTH)
    assert r.status_code == 200 and len(r.json()) == 5
    d = env.client.get("/v2/compliance/frameworks/pci-dss-4.0-req6", headers=AUTH).json()
    assert "not a certification" in d["disclaimer"] and d["items"][0]["id"] == "6.1.1"
    assert env.client.get("/v2/compliance/frameworks/nope", headers=AUTH).status_code == 404


# ------------------------------------------------------------------ the ASVS benchmark


def test_only_a_person_marks_an_asvs_requirement_met(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])  # CWE-89, open
    url = f"/v2/projects/{env.asset_id}/asvs"
    b = env.client.get(url, params={"level": 2}, headers=AUTH).json()
    assert len(b["requirements"]) == 259 and "absence of findings" in b["disclaimer"]
    rows = {r["id"]: r for r in b["requirements"]}
    assert rows["V5.3.4"]["status"] == "issues_open" and rows["V5.3.4"]["issues"] == 1
    assert rows["V2.1.1"]["status"] == "not_assessed"
    assert "met" not in b["counts"]  # never by itself

    assert env.client.put(f"{url}/V2.1.1", json={"status": "met"}, headers=AUTH).status_code == 422
    assert env.client.put(f"{url}/V9.9.9", json={"status": "met", "note": "x"}, headers=AUTH).status_code == 422  # fmt: skip
    assert env.client.put(f"{url}/nope", json={"status": "met", "note": "x"}, headers=AUTH).status_code == 404  # fmt: skip
    bad_link = {"status": "met", "note": "x", "links": ["javascript:alert(1)"]}
    assert env.client.put(f"{url}/V2.1.1", json=bad_link, headers=AUTH).status_code == 422
    ok = env.client.put(f"{url}/V5.3.4", json={"status": "met", "note": "ORM only",
                                               "links": ["/app/projects/x/issues"]}, headers=AUTH)  # fmt: skip
    assert ok.status_code == 200 and ok.json()["status"] == "met"
    rows = {r["id"]: r for r in env.client.get(url, headers=AUTH).json()["requirements"]}
    assert rows["V5.3.4"]["status"] == "met" and rows["V5.3.4"]["conflict"] is True  # Issues open

    with env.sessions() as s:
        e = Engagement(org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, name="Q3 test",
                       engagement_type="pentest", checklist="asvs-4.0.3-l2")  # fmt: skip
        s.add(e)
        s.flush()
        s.add_all([
            EngagementChecklistItem(org_id=DEFAULT_ORG_ID, engagement_id=e.id, item_id="V3.2.1", status="fail"),
            EngagementChecklistItem(org_id=DEFAULT_ORG_ID, engagement_id=e.id, item_id="V3.2.2", status="pass"),
        ])  # fmt: skip
        s.commit()
    rows = {r["id"]: r for r in env.client.get(url, headers=AUTH).json()["requirements"]}
    assert (rows["V3.2.1"]["status"], rows["V3.2.1"]["source"]) == ("not_met", "assessment")
    assert rows["V3.2.2"]["status"] == "tested"  # passed a test: evidence, not "met"
    assert env.client.put(f"{url}/V5.3.4", json={"status": None}, headers=AUTH).status_code == 200
    with env.sessions() as s:
        actions = [e.action for e in repo.list_audit_entries(s)]
        assert actions.count("compliance.status_set") == 1 and "compliance.status_cleared" in actions  # fmt: skip
    assert env.client.get(f"/v2/projects/{env.other_asset_id}/asvs", headers=AUTH).status_code == 404  # fmt: skip


# ------------------------------------------------------------------ the evidence pack


def _history(env: Env) -> None:
    assert put(env).status_code == 200  # the starter SLA policy: HIGH 30 days, CRITICAL 7
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH), finding(3, Severity.CRITICAL),
               finding(4, Severity.HIGH)])  # fmt: skip
    days = {  # first seen, fixed (days ago)
        "Problem 1": (50, 25),  # due 20 days ago, fixed before it: met
        "Problem 2": (40, None),  # due 10 days ago, still open: open past deadline
        "Problem 3": (30, 10),  # due 23 days ago, fixed after it: missed
        "Problem 4": (5, None),  # due in 25 days: not in the period
    }
    with env.sessions() as s:
        for issue in s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id)):
            seen, fixed = days[issue.title]
            issue.first_seen_at = NOW - timedelta(days=seen)
            if fixed is not None:
                issue.state, issue.fixed_at = "fixed", NOW - timedelta(days=fixed)
        s.add(RiskAcceptance(
            org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, decision="accept", justification="WAF rule",
            controls="WAF", expires_at=NOW + timedelta(days=30), state="approved",
            requested_by="token:alice", requested_at=NOW - timedelta(days=12),
            decided_by="token:bob", decided_at=NOW - timedelta(days=11),
        ))  # fmt: skip
        s.commit()
        repo.append_audit_entry(s, actor="token:zq-other-org-actor", action="zq.other.action",
                                target="their-thing", payload={}, org_id=OTHER_ORG)  # fmt: skip


def _unzip(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: z.read(n) for n in z.namelist()}


FRAMEWORKS = ["pci-dss-4.0-req6", "iso27001-2022-a8.8", "soc2-2017-cc7.1", "asvs-4.0.3",
              "owasp-top10-2021"]  # fmt: skip


def test_an_evidence_pack_holds_what_an_auditor_needs_and_checks_itself(
    env: Env, tmp_path: Path
) -> None:
    _history(env)
    start, end = (NOW - timedelta(days=59)).date(), NOW.date()
    body = {"start": str(start), "end": str(end), "frameworks": FRAMEWORKS}
    pre = env.client.post("/v2/evidence-packs/preview", json=body, headers=AUTH)
    assert pre.status_code == 200, pre.text
    assert pre.json()["sla"] == {"met": 1, "missed": 1, "open_past_deadline": 1, "exempt": 0,
                                 "adherence": round(1 / 3, 4)}  # fmt: skip
    assert pre.json()["signing"] is False
    alice = token(env, "Alice")
    r = env.client.post("/v2/evidence-packs", json=body, headers=alice)
    assert r.status_code == 201, r.text
    pack = r.json()
    assert pack["signed"] is False and pack["summary"]["risk_acceptances"] == 1
    assert pack["summary"]["audit"]["ok"] is True

    got = env.client.get(f"/v2/evidence-packs/{pack['id']}/bundle", headers=AUTH)
    assert got.status_code == 200 and got.headers["content-type"] == "application/zip"
    assert got.headers["x-content-sha256"] == pack["sha256"]
    files = _unzip(got.content)
    assert set(files) == {"README.txt", "audit-extract.json", "evidence.json", "evidence.pdf",
                          "manifest.json", "verify.py"}  # fmt: skip
    assert files["evidence.pdf"].startswith(b"%PDF")
    ev = json.loads(files["evidence.json"])
    assert ev["sla"]["met"] == 1 and ev["risk_acceptances"]["rows"][0]["second_person"] is True
    assert ev["scan_coverage"]["rows"][0]["full_scans"] == 1
    pci = next(f for f in ev["frameworks"] if f["id"] == "pci-dss-4.0-req6")
    c624 = next(c for c in pci["controls"] if c["id"] == "6.2.4")
    assert "2 open Issues" in c624["evidence"][0]["here"]  # Problems 2 and 4, CWE-89
    asvs = next(f for f in ev["frameworks"] if f["id"] == "asvs-4.0.3")
    assert asvs["projects"][0]["issues_open"] >= 1
    assert b"zq" not in files["audit-extract.json"] and b"zq" not in files["evidence.json"]
    assert "not a certification" in ev["disclaimer"]

    # The auditor's check: the standalone verifier, run as a separate program on the files.
    out = tmp_path / "pack"
    for name, data in files.items():
        (out / name).parent.mkdir(parents=True, exist_ok=True)
        (out / name).write_bytes(data)
    run = subprocess.run([sys.executable, str(out / "verify.py")], capture_output=True, text=True,
                         timeout=60, check=False)  # fmt: skip
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Files against manifest.json: OK" in run.stdout and "NOT signed" in run.stdout
    (out / "evidence.json").write_bytes(files["evidence.json"].replace(b'"met": 1', b'"met": 9'))
    run = subprocess.run([sys.executable, str(out / "verify.py")], capture_output=True, text=True,
                         timeout=60, check=False)  # fmt: skip
    assert run.returncode == 1 and "evidence.json does not match" in run.stdout

    listed = env.client.get("/v2/evidence-packs", headers=AUTH).json()
    assert [p["id"] for p in listed] == [pack["id"]]
    assert env.client.get("/v2/evidence-packs", headers=OTHER).json() == []
    assert env.client.get(f"/v2/evidence-packs/{pack['id']}/bundle", headers=OTHER).status_code == 404  # fmt: skip
    with env.sessions() as s:
        assert "evidence_pack.created" in [e.action for e in repo.list_audit_entries(s)]

    bad = {"start": str(end), "end": str(start), "frameworks": []}
    assert env.client.post("/v2/evidence-packs", json=bad, headers=AUTH).status_code == 422
    long = {"start": "2020-01-01", "end": str(end), "frameworks": []}
    assert env.client.post("/v2/evidence-packs", json=long, headers=AUTH).status_code == 422
    unknown = {**body, "frameworks": ["nist-800-53"]}
    assert env.client.post("/v2/evidence-packs", json=unknown, headers=AUTH).status_code == 422
    reader = token(env, "Reader", ["scans:read"])
    assert env.client.post("/v2/evidence-packs", json=body, headers=reader).status_code == 403


def test_a_pack_is_signed_when_a_key_is_set_and_never_passes_unsigned_for_signed(
    env: Env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from core.attest import cosign
    from core.evidence import pack

    key = tmp_path / "cosign.key"
    key.write_text("not really a key")
    monkeypatch.setenv(pack.KEY_ENV, str(key))
    signed: list[bytes] = []

    def fake_sign(blob: Path, k: Path, out: Path) -> None:
        signed.append(blob.read_bytes())
        out.write_text('{"fake": "bundle"}')

    monkeypatch.setattr(cosign, "sign_blob", fake_sign)
    body = {"start": str(date.today()), "end": str(date.today()), "frameworks": []}
    r = env.client.post("/v2/evidence-packs", json=body, headers=AUTH)
    assert r.status_code == 201 and r.json()["signed"] is True
    files = _unzip(env.client.get(f"/v2/evidence-packs/{r.json()['id']}/bundle", headers=AUTH).content)  # fmt: skip
    assert files["manifest.json.sig"] == b'{"fake": "bundle"}'
    assert signed == [files["manifest.json"]]  # the signature is over exactly this manifest
    assert verifier.verify_pack(files)["signed"] is True

    def broken(blob: Path, k: Path, out: Path) -> None:
        raise cosign.AttestError("cosign failed: bad password")

    monkeypatch.setattr(cosign, "sign_blob", broken)
    r = env.client.post("/v2/evidence-packs", json=body, headers=AUTH)
    assert r.status_code == 503 and "could not sign" in r.json()["detail"]
    with env.sessions() as s:
        assert len(s.scalars(select(EvidencePack)).all()) == 1  # no unsigned pack instead
