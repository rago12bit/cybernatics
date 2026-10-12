"""core.sandbox.firecracker: the fix agent's test run in a microVM. What can be checked without
KVM -- the VM document, the init script, reading the result, unpacking an image safely, the
orchestration, and how the fix agent's sandbox chooses it. Booting it for real is
tests/integration/test_firecracker_live.py (skipped without /dev/kvm)."""

from __future__ import annotations

import io
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from core.fixagent import sandbox
from core.sandbox import firecracker as fc


def test_memory_in_docker_notation_becomes_mib() -> None:
    assert fc.memory_mib("2g") == 2048
    assert fc.memory_mib("512m") == 512
    assert fc.memory_mib("1.5G") == 1536
    assert fc.memory_mib("64m") == 128  # a floor: a guest kernel needs some room
    assert fc.memory_mib(str(300 * 1024 * 1024)) == 300
    with pytest.raises(ValueError):
        fc.memory_mib("lots")


def test_the_vm_has_the_kernel_two_disks_and_no_network(tmp_path: Path) -> None:
    cfg = fc.FirecrackerConfig(kernel=tmp_path / "vmlinux")
    doc = fc.vm_config(cfg, tmp_path / "r.ext4", tmp_path / "w.ext4", vcpus=2, mem_mib=1024)
    assert doc["network-interfaces"] == []
    boot = doc["boot-source"]
    assert isinstance(boot, dict) and "init=/bulwark-init" in boot["boot_args"]
    assert "root=/dev/vda" in boot["boot_args"] and "reboot=k" in boot["boot_args"]
    drives = doc["drives"]
    assert isinstance(drives, list)
    assert [(d["drive_id"], d["is_root_device"]) for d in drives] == [("rootfs", True),
                                                                      ("work", False)]  # fmt: skip
    assert doc["machine-config"] == {"vcpu_count": 2, "mem_size_mib": 1024}


def test_the_result_is_the_last_marker_init_printed() -> None:
    # The test suite printed a marker of its own; init's comes after, once everything else is dead.
    console = "boot...\nBULWARK-EXIT 0\nFAILED test_x\nBULWARK-EXIT 1\n[ reboot ]\n"
    assert fc.exit_code(console) == 1
    assert fc.exit_code("Kernel panic - not syncing: VFS: Unable to mount root fs\n") is None
    assert fc.exit_code("say BULWARK-EXIT 0 inline\n") is None  # only a whole line counts


def test_init_is_valid_sh_and_ends_the_vm_with_a_reboot() -> None:
    proc = subprocess.run(["sh", "-n"], input=fc.INIT_SCRIPT.encode(), capture_output=True)
    assert proc.returncode == 0, proc.stderr
    lines = fc.INIT_SCRIPT.splitlines()
    assert lines[0] == "#!/bin/sh"
    # Everything else killed before the marker; reboot (not power-off: Firecracker x86 can't).
    assert lines.index("kill -9 -1 2>/dev/null") < lines.index('echo "BULWARK-EXIT $code"')
    assert lines[-1] == "echo b > /proc/sysrq-trigger"


def test_the_host_check_names_what_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("BULWARK_FIRECRACKER_KERNEL", raising=False)
    kernel = tmp_path / "vmlinux"
    with pytest.raises(fc.FirecrackerError, match="no KVM"):
        fc.check_host(fc.FirecrackerConfig(kernel=kernel, kvm=tmp_path / "kvm"))
    kvm = tmp_path / "kvm"
    kvm.write_text("")
    with pytest.raises(fc.FirecrackerError, match="not installed"):
        fc.check_host(fc.FirecrackerConfig(kernel=kernel, kvm=kvm, firecracker="no-such-fc"))
    with pytest.raises(fc.FirecrackerError, match="BULWARK_FIRECRACKER_KERNEL"):
        fc.FirecrackerConfig.from_env()


def _tar(members: list[tuple[str, dict[str, Any], bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, attrs, data in members:
            info = tarfile.TarInfo(name)
            for k, v in attrs.items():
                setattr(info, k, v)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data) if data else None)
    return buf.getvalue()


def test_an_image_unpacks_without_writing_outside_or_keeping_setuid(tmp_path: Path) -> None:
    outside, dest = tmp_path / "outside", tmp_path / "dest"
    outside.mkdir()
    dest.mkdir()
    sym, lnk, dirt, chr_ = tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.CHRTYPE
    archive = tmp_path / "image.tar"
    archive.write_bytes(_tar([
        ("bin", {"type": dirt, "mode": 0o555}, b""),
        ("bin/su", {"mode": 0o4755}, b"#!x"),
        ("usr/bin/python3", {"type": sym, "linkname": "/usr/local/bin/python3.12"}, b""),
        ("escape", {"type": sym, "linkname": str(outside)}, b""),
        ("escape/pwned", {}, b"bad"),  # through a link that leads out: not written
        ("evil", {"type": sym, "linkname": str(outside / "file")}, b""),
        ("evil", {}, b"replaced"),  # a file over a link: the link goes, nothing written through it
        ("../up", {}, b"bad"),
        ("hardout", {"type": lnk, "linkname": "../../etc/passwd"}, b""),
        ("dev/null", {"type": chr_}, b""),
    ]))  # fmt: skip
    fc._unpack(archive, dest)
    assert os.listdir(outside) == [] and not (tmp_path / "up").exists()
    assert os.readlink(dest / "usr/bin/python3") == "/usr/local/bin/python3.12"  # kept as written
    assert (dest / "evil").read_bytes() == b"replaced" and not (dest / "evil").is_symlink()
    assert (dest / "bin/su").stat().st_mode & 0o7777 == 0o755
    assert not (dest / "hardout").exists() and not (dest / "dev/null").exists()


class _Fake:
    """Records commands; `docker create` answers an id, `firecracker` prints `console`."""

    def __init__(self, console: str = "", timeout: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.console, self.timeout = console, timeout

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(list(argv))
        if argv[:2] == ["docker", "create"]:
            return subprocess.CompletedProcess(argv, 0, b"cid123\n", b"")
        if argv[:2] == ["docker", "export"]:
            kw["stdout"].write(_tar([("usr", {"type": tarfile.DIRTYPE}, b"")]))
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[0] == "mkfs.ext4":
            Path(argv[-2]).write_bytes(b"ext4")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[0] == "firecracker":
            if self.timeout:
                raise subprocess.TimeoutExpired(argv, 5, output=b"still booting")
            return subprocess.CompletedProcess(argv, 0, self.console.encode(), b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def _run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fake: _Fake) -> fc.MicroVMResult:
    monkeypatch.setattr(fc, "check_host", lambda cfg: None)
    monkeypatch.setattr(fc.subprocess, "run", fake)
    monkeypatch.setattr(fc, "scratch_dir", lambda: tmp_path)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "test_x.py").write_text("def test(): pass\n")
    cfg = fc.FirecrackerConfig(kernel=tmp_path / "vmlinux")
    return fc.run_in_microvm(cfg, checkout, "python:3.12-slim", "pytest -q",
                             vcpus=2, mem_mib=1024, timeout_s=5)  # fmt: skip


def test_a_run_builds_both_disks_boots_without_the_api_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _Fake("...\nBULWARK-EXIT 0\n")
    result = _run(monkeypatch, tmp_path, fake)
    assert (result.exit_code, result.timed_out) == (0, False)
    tools = [c[0] if c[0] != "docker" else " ".join(c[:2]) for c in fake.calls]
    assert tools == ["docker create", "docker export", "docker rm", "mkfs.ext4", "mkfs.ext4",
                     "firecracker"]  # fmt: skip
    assert fake.calls[-1][1:3] == ["--no-api", "--config-file"]
    assert [p.name for p in tmp_path.iterdir()] == ["checkout"]  # its scratch directory is gone


def test_a_run_that_outlives_its_time_is_a_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _run(monkeypatch, tmp_path, _Fake(timeout=True))
    assert result.timed_out and result.exit_code is None and result.console == "still booting"


def test_the_fix_agent_uses_a_microvm_only_when_asked_and_never_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    spec = sandbox.TestRunSpec(image="python:3.12-slim", command="pytest -q", memory="1g", cpus=1.5)
    seen: dict[str, Any] = {}

    def fake_vm(cfg: Any, checkout: Path, image: str, command: str, **kw: Any) -> Any:
        seen.update(kw, image=image, command=command)
        return fc.MicroVMResult(1, "E   assert 1 == 2\nBULWARK-EXIT 1\n")

    monkeypatch.setenv("BULWARK_TEST_SANDBOX", "firecracker")
    monkeypatch.setenv("BULWARK_FIRECRACKER_KERNEL", str(tmp_path / "vmlinux"))
    monkeypatch.setattr(fc, "run_in_microvm", fake_vm)
    step = sandbox.run_tests(tmp_path, spec)
    assert not step.passed and step.detail.startswith("exit code 1:")
    assert seen == {"vcpus": 2, "mem_mib": 1024, "timeout_s": spec.timeout_s,
                    "image": "python:3.12-slim", "command": "pytest -q"}  # fmt: skip

    def no_kvm(*a: Any, **kw: Any) -> Any:
        raise fc.FirecrackerError("/dev/kvm does not exist: this host has no KVM")

    monkeypatch.setattr(fc, "run_in_microvm", no_kvm)
    with pytest.raises(sandbox.SandboxError, match="no KVM"):  # not a silent Docker fallback
        sandbox.run_tests(tmp_path, spec)
