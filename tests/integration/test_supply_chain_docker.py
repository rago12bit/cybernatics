"""Real Syft and cosign in Docker: an SBOM that validates against the CycloneDX schema, and signatures that verify."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from core.attest import (
    PREDICATE_TYPE,
    AttestError,
    attest_blob,
    sign_blob,
    verify_attestation,
    verify_blob,
)
from core.attest.cosign import COSIGN_IMAGE
from core.sbom import SYFT_IMAGE, generate_sbom

FIX = Path(__file__).parent.parent / "fixtures"


def _ready(*images: str) -> bool:
    if (
        not shutil.which("docker")
        or subprocess.run(["docker", "info"], capture_output=True).returncode != 0
    ):
        return False
    return all(
        subprocess.run(["docker", "image", "inspect", i], capture_output=True).returncode == 0
        for i in images
    )


pytestmark = pytest.mark.skipif(
    not _ready(SYFT_IMAGE, COSIGN_IMAGE), reason="docker or the syft/cosign images are missing"
)


def _validator() -> Draft7Validator:
    load = lambda n: json.loads((FIX / "cyclonedx" / n).read_text())  # noqa: E731
    reg = Registry().with_resources(
        [
            (
                "http://cyclonedx.org/schema/spdx.schema.json",
                Resource.from_contents(load("spdx.schema.json")),
            ),
            (
                "http://cyclonedx.org/schema/jsf-0.82.schema.json",
                Resource.from_contents(load("jsf-0.82.schema.json")),
            ),
        ]
    )
    return Draft7Validator(load("bom-1.6.schema.json"), registry=reg)


def test_sbom_of_a_real_project_validates_against_the_cyclonedx_16_schema(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    for f in ("package-lock.json", "requirements.txt"):
        if (FIX / "vuln-deps" / f).exists():
            shutil.copy(FIX / "vuln-deps" / f, src / f)
    sbom = generate_sbom(src, "vuln-deps")
    assert sbom.spec_version == "1.6" and sbom.components > 0 and sbom.ecosystems.get("npm")
    errors = list(_validator().iter_errors(json.loads(sbom.raw)))
    assert errors == [], errors[:3]
    assert "lodash" in sbom.raw.decode()  # the fixture's deliberately old dependency is listed


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("keys")
    env = {**os.environ, "COSIGN_PASSWORD": "test-only-password"}
    for name in ("a", "b"):
        subprocess.run(
            ["docker", "run", "--rm", "--network=none", f"--user={os.getuid()}:{os.getgid()}", "-e", "COSIGN_PASSWORD", "-e", "HOME=/tmp",
             "-v", f"{d}:/w", "-w", "/w", COSIGN_IMAGE, "generate-key-pair", "--output-key-prefix", name],
            env=env, check=True, capture_output=True,
        )  # fmt: skip
    os.environ["COSIGN_PASSWORD"] = "test-only-password"
    return {"a.key": d / "a.key", "a.pub": d / "a.pub", "b.pub": d / "b.pub"}


def test_signature_verifies_and_breaks_on_tamper_or_the_wrong_key(
    tmp_path: Path, keys: dict[str, Path]
) -> None:
    f = tmp_path / "scan.json"
    f.write_text('{"findings": []}')
    bundle = tmp_path / "scan.json.sig.bundle"
    sign_blob(f, keys["a.key"], bundle)
    verify_blob(f, keys["a.pub"], bundle)
    with pytest.raises(AttestError, match="invalid signature"):
        verify_blob(f, keys["b.pub"], bundle)
    f.write_text('{"findings": [1]}')
    with pytest.raises(AttestError, match="invalid signature"):
        verify_blob(f, keys["a.pub"], bundle)


def test_wrong_password_is_reported(
    tmp_path: Path, keys: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    f = tmp_path / "x.json"
    f.write_text("{}")
    monkeypatch.setenv("COSIGN_PASSWORD", "not-the-password")
    with pytest.raises(AttestError, match="cosign failed"):
        sign_blob(f, keys["a.key"], tmp_path / "o.bundle")


def test_attestation_binds_predicate_subject_and_type(
    tmp_path: Path, keys: dict[str, Path]
) -> None:
    f = tmp_path / "scan.json"
    f.write_text('{"findings": []}')
    bundle = tmp_path / "prov.bundle"
    attest_blob(f, {"result": {"uniqueFindings": 0}}, PREDICATE_TYPE, keys["a.key"], bundle)
    stmt = verify_attestation(f, PREDICATE_TYPE, keys["a.pub"], bundle)
    assert (
        stmt["predicate"] == {"result": {"uniqueFindings": 0}}
        and stmt["predicateType"] == PREDICATE_TYPE
    )
    assert stmt["subject"][0]["name"] == "scan.json"
    with pytest.raises(AttestError, match="predicate type"):
        verify_attestation(f, PREDICATE_TYPE + "-other", keys["a.pub"], bundle)
    with pytest.raises(AttestError, match="digests do not match"):
        other = tmp_path / "other.json"
        other.write_text("different")
        verify_attestation(other, PREDICATE_TYPE, keys["a.pub"], bundle)
    # cosign v3.1.3's own refusal (seen 2026-10-14). Any AttestError passed here before -- a missing
    # key file, docker failing, a timeout -- none of which shows the signature check works.
    with pytest.raises(AttestError, match="accepted signatures do not match threshold, Found: 0"):
        verify_attestation(f, PREDICATE_TYPE, keys["b.pub"], bundle)
