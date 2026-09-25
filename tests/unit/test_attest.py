from __future__ import annotations

import base64
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from cli.main import app
from core.attest import PREDICATE_TYPE, AttestError, build_predicate, cosign, sha256_file
from core.attest.cosign import COSIGN_IMAGE, _safe_name, statement_of
from core.sbom import SbomError, SyftAdapter, summarize

runner = CliRunner()

SCAN = {
    "tool_status": {"bandit": {"status": "ok", "findings": 2}, "trivy": {"status": "error", "findings": 0}},
    "stats": {"raw_findings": 5, "unique_findings": 4, "ignored_findings": 1},
    "findings": [{"scoring": {"normalized_severity": s}} for s in ("HIGH", "HIGH", "LOW", "bogus")],
}  # fmt: skip


# ---- provenance predicate -----------------------------------------------------------------------


def test_predicate_has_counts_tools_artifact_digests_and_no_findings(tmp_path: Path) -> None:
    f = tmp_path / "scan.json"
    f.write_text('{"x":1}')
    p = build_predicate(
        SCAN, {"scan.json": f}, {"bandit": "bulwark/bandit:1", "trivy": "bulwark/trivy:1"},
        {"label": "o/r", "commit": "abc", "ref": ""}, datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        resolve_image=lambda i: f"sha256:{i[-1] * 4}",
    )  # fmt: skip
    assert p["result"] == {"uniqueFindings": 4, "rawFindings": 5, "ignoredFindings": 1,
                           "bySeverity": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 1, "INFO": 0}}  # fmt: skip
    assert p["source"] == {"label": "o/r", "commit": "abc"}  # empty values are dropped
    assert p["tools"][0] == {
        "name": "bandit",
        "status": "ok",
        "findings": 2,
        "image": "bulwark/bandit:1",
        "imageId": "sha256:1111",
    }
    assert p["artifacts"] == [{"name": "scan.json", "sha256": sha256_file(f), "bytes": 7}]
    assert p["generatedAt"] == "2026-01-02T03:04:05Z"
    assert "findings" not in p and "not attest that the findings are correct" in p["limitations"]


def test_predicate_tolerates_an_unknown_image_id() -> None:
    p = build_predicate(SCAN, {}, {"bandit": "b"}, resolve_image=lambda i: None)
    assert "imageId" not in p["tools"][0]


def test_sha256_file(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"abc")
    assert (
        sha256_file(tmp_path / "a")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


# ---- how cosign is launched ---------------------------------------------------------------------


class Captured:
    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.argv: list[str] = []
        self.returncode, self.stderr = returncode, stderr

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        self.argv = argv
        work = Path(next(a for a in argv if a.endswith(":/work")).rsplit(":", 1)[0])
        (work / "out.bundle").write_text("{}")  # what cosign would have produced
        return subprocess.CompletedProcess(argv, self.returncode, b"", self.stderr.encode())


@pytest.fixture
def keyfile(tmp_path: Path) -> Path:
    k = tmp_path / "cosign.key"
    k.write_text("PRIVATE")
    return k


def test_cosign_runs_in_a_locked_down_container(
    tmp_path: Path, keyfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = Captured()
    monkeypatch.setattr(subprocess, "run", cap)
    monkeypatch.setenv("COSIGN_PASSWORD", "s3cret-pw")
    blob = tmp_path / "scan.json"
    blob.write_text("{}")
    cosign.sign_blob(blob, keyfile, tmp_path / "o.bundle")
    a = cap.argv
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ):
        assert flag in a
    assert f"{keyfile.resolve()}:/keys/cosign.key:ro" in a  # the key is mounted read-only
    assert COSIGN_IMAGE in a and "@sha256:" in COSIGN_IMAGE  # pinned by digest
    assert "--tlog-upload=false" in a and "--use-signing-config=false" in a
    assert "COSIGN_PASSWORD" in a and not any(
        "s3cret-pw" in x for x in a
    )  # by name, never the value
    assert (tmp_path / "o.bundle").exists()


def test_password_is_not_forwarded_when_unset(
    tmp_path: Path, keyfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = Captured()
    monkeypatch.setattr(subprocess, "run", cap)
    monkeypatch.delenv("COSIGN_PASSWORD", raising=False)
    (tmp_path / "b").write_text("x")
    cosign.sign_blob(tmp_path / "b", keyfile, tmp_path / "o")
    assert "COSIGN_PASSWORD" not in cap.argv


def test_failures_are_readable_and_hint_at_the_password(
    tmp_path: Path, keyfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        Captured(1, "noise\nError: getting private key: decrypt: wrong password\n"),
    )
    (tmp_path / "b").write_text("x")
    with pytest.raises(AttestError, match=r"wrong password.*COSIGN_PASSWORD"):
        cosign.sign_blob(tmp_path / "b", keyfile, tmp_path / "o")


def test_missing_key_docker_and_timeout(
    tmp_path: Path, keyfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "b").write_text("x")
    with pytest.raises(AttestError, match="key file not found"):
        cosign.sign_blob(tmp_path / "b", tmp_path / "nokey", tmp_path / "o")

    def no_docker(*a: Any, **k: Any) -> Any:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", no_docker)
    with pytest.raises(AttestError, match="docker is not installed"):
        cosign.sign_blob(tmp_path / "b", keyfile, tmp_path / "o")

    def slow(*a: Any, **k: Any) -> Any:
        raise subprocess.TimeoutExpired("docker", 1)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(AttestError, match="timed out"):
        cosign.sign_blob(tmp_path / "b", keyfile, tmp_path / "o")


@pytest.mark.parametrize(
    "name,expected",
    [
        ("scan.json", "scan.json"),
        ("-rf", "artifact"),
        ("a b.json", "artifact"),
        ("x" * 200, "artifact"),
        ("..", "artifact"),
    ],
)
def test_odd_file_names_never_reach_cosign_as_flags_or_paths(name: str, expected: str) -> None:
    assert _safe_name(Path("/x") / name) == expected


def test_statement_of_reads_the_dsse_payload_and_rejects_other_files(tmp_path: Path) -> None:
    stmt = {"_type": "https://in-toto.io/Statement/v0.1", "predicate": {"a": 1}}
    b = tmp_path / "b"
    b.write_text(
        json.dumps(
            {"dsseEnvelope": {"payload": base64.b64encode(json.dumps(stmt).encode()).decode()}}
        )
    )
    assert statement_of(b) == stmt
    (tmp_path / "bad").write_text('{"messageSignature": {}}')
    with pytest.raises(AttestError, match="not an attestation bundle"):
        statement_of(tmp_path / "bad")


# ---- SBOM ---------------------------------------------------------------------------------------


def test_syft_command_is_a_fixed_scan_of_the_mounted_directory() -> None:
    cmd = SyftAdapter("my proj").build_command(Path("/target"), Path("/out/result.json"))
    assert cmd == [
        "scan",
        "dir:/target",
        "--output",
        "cyclonedx-json@1.6=/out/result.json",
        "--source-name",
        "my proj",
        "--quiet",
    ]
    assert SyftAdapter().parse(b"{}") == []


def test_summarize_counts_components_by_ecosystem_and_rejects_non_cyclonedx() -> None:
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"purl": "pkg:npm/a@1"},
            {"purl": "pkg:pypi/b@2"},
            {"purl": "pkg:npm/c@3"},
            {"name": "nopurl"},
        ],
    }
    s = summarize(json.dumps(doc).encode())
    assert (s.components, s.spec_version, s.ecosystems) == (4, "1.6", {"npm": 2, "pypi": 1})
    for bad in (
        b"nope",
        b'{"bomFormat": "SPDX"}',
        b'{"bomFormat": "CycloneDX", "components": 5}',
        b"[]",
    ):
        with pytest.raises(SbomError):
            summarize(bad)


# ---- CLI ----------------------------------------------------------------------------------------


def test_cli_verify_needs_a_bundle_and_reports_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f, pub = tmp_path / "scan.json", tmp_path / "cosign.pub"
    f.write_text("{}")
    pub.write_text("PUB")
    r = runner.invoke(app, ["attest", "verify", str(f), "--pub", str(pub)])
    assert r.exit_code == 2 and "no signature or attestation" in r.output

    (tmp_path / "scan.json.sig.bundle").write_text("{}")

    def bad(*a: Any, **k: Any) -> None:
        raise AttestError("cosign failed: invalid signature")

    monkeypatch.setattr("core.attest.verify_blob", bad)
    r = runner.invoke(app, ["attest", "verify", str(f), "--pub", str(pub)])
    assert r.exit_code == 1 and "invalid signature" in r.output


def test_cli_verify_rejects_a_file_whose_digest_differs_from_the_attested_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f, pub = tmp_path / "scan.json", tmp_path / "cosign.pub"
    f.write_text("{}")
    pub.write_text("PUB")
    (tmp_path / "scan.json.provenance.bundle").write_text("{}")
    stmt = {"predicate": {"artifacts": [{"name": "scan.json", "sha256": "0" * 64}], "result": {}}}
    monkeypatch.setattr("core.attest.verify_attestation", lambda *a, **k: stmt)
    r = runner.invoke(app, ["attest", "verify", str(f), "--pub", str(pub)])
    assert r.exit_code == 1 and "attested digest differs" in r.output


def test_cli_provenance_builds_the_predicate_and_signs_it(
    tmp_path: Path, keyfile: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(SCAN))
    (tmp_path / "sbom.json").write_text("{}")
    seen: dict[str, Any] = {}

    def fake(blob: Path, predicate: dict[str, Any], ptype: str, key: Path, out: Path) -> None:
        seen.update(predicate=predicate, ptype=ptype, key=key)
        out.write_text("{}")

    monkeypatch.setattr("core.attest.attest_blob", fake)
    monkeypatch.setattr("core.attest.provenance.image_id", lambda i: None)
    r = runner.invoke(app, ["attest", "provenance", str(scan), "--scan", str(scan), "--key", str(keyfile),
                            "--artifact", f"sbom={tmp_path / 'sbom.json'}", "--commit", "abc"])  # fmt: skip
    assert r.exit_code == 0, r.output
    assert seen["ptype"] == PREDICATE_TYPE and seen["predicate"]["source"] == {"commit": "abc"}
    assert {a["name"] for a in seen["predicate"]["artifacts"]} == {"scan.json", "sbom"}
    assert (tmp_path / "scan.json.provenance.bundle").exists()
    assert "PRIVATE" not in json.dumps(seen["predicate"])


def test_cli_provenance_rejects_unreadable_scan_output(tmp_path: Path, keyfile: Path) -> None:
    bad = tmp_path / "scan.json"
    bad.write_text("nope")
    r = runner.invoke(
        app, ["attest", "provenance", str(bad), "--scan", str(bad), "--key", str(keyfile)]
    )
    assert r.exit_code == 2
