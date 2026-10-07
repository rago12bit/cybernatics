"""Week 69 under REAL Row-Level Security (migration 0041): what a project's code uses, its VEX
statements, a person's compliance statuses and the evidence packs belong to one organization; and an
evidence pack's audit-log extract shows another organization's entries as hashes only. Runs as
`bulwark_worker`. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head)."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.compliance import asvs
from core.evidence import pack, verifier
from core.persistence.models import CodeUsage, ComplianceStatus, EvidencePack, VexStatement
from core.reachability.golang import GoUsage, scan_file
from core.tenancy import set_session_org
from core.vex import export, service
from core.vex.evidence import record_usage
from tests.integration.test_advisories_rls_docker import _sbom, advisories  # noqa: F401
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401

XNET = "pkg:golang/golang.org/x/net@v0.0.0-20210428140749-89ef3d95e781"
TOKENIZER = b'package main\nimport h "golang.org/x/net/html"\nfunc main() { z := h.NewTokenizer(nil); z.Next() }\n'  # noqa: E501
MODELS = (CodeUsage, VexStatement, ComplianceStatus, EvidencePack)


def test_vex_compliance_and_packs_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str], advisories: None  # noqa: F811
) -> None:
    a, b = two_orgs
    today = datetime.now(timezone.utc).date()  # a pack's days are UTC days (pack.window)
    with sessions() as s:
        set_session_org(s, a)
        _sbom(s, a, XNET)
        asset = s.scalars(select(CodeUsage.asset_id)).first()  # none yet: RLS hides other orgs'
        assert asset is None
        from core.persistence.models import Asset

        asset_id = s.scalars(select(Asset.id).where(Asset.org_id == a)).one()
        u = GoUsage(module="example.com/a")
        u.add("main.go", scan_file(TOKENIZER), test=False)
        record_usage(s, org_id=a, asset_id=asset_id, scan_id=None, go=u)  # type: ignore[arg-type]
        drafted = service.draft(s, a, "CVE-2021-33194", actor="token:zq-alice")
        assert drafted.proposed == 1
        service.confirm(s, a, drafted.ids[0], actor="token:zq-bob")
        asvs.set_status(s, a, asset_id, "V5.3.4", status="met", note="ORM only", links=[],
                        actor="token:zq-alice")  # fmt: skip
        pack.create(s, a, today, today, ["pci-dss-4.0-req6"], actor="token:zq-alice")
        assert [m.__tablename__ for m in MODELS if s.scalar(select(func.count()).select_from(m))] == [  # noqa: E501
            "code_usage", "vex_statements", "compliance_statuses", "evidence_packs"]  # fmt: skip
        statements = export.openvex(s, a, s.get(Asset, asset_id))["statements"]
        assert [st["status"] for st in statements] == ["not_affected"]

    with sessions() as s:
        set_session_org(s, b)
        for model in MODELS:
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert service.uses(s, b, "CVE-2021-33194") == []
        built = pack.build(s, b, today, today, [], actor="token:zq-carol")
        files = {n: z for n, z in _unzip(built.bundle).items()}
        extract = json.loads(files["audit-extract.json"])
        assert b"zq-alice" not in files["audit-extract.json"]  # A's entries: hashes only
        assert b"zq-bob" not in files["evidence.json"]
        assert any(e.get("withheld") for e in extract["entries"])
        assert verifier.verify_extract(extract)["ok"]


def _unzip(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: z.read(n) for n in z.namelist()}
