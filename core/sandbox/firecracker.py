"""Firecracker: the fix agent's "run this project's own tests" step in a microVM (plan §22.1,
milestone M10, ADR-0031).

Docker shares the host's kernel with whatever runs inside; a microVM does not -- the project's test
suite (arbitrary code, by definition) runs under its own guest kernel, behind KVM's hardware
virtualization boundary. Scanners stay on Docker or gVisor (`core.sandbox.gvisor_runtime`): they
only read code, and are far more numerous.

How a run works, every step without root on the host:

1. **Root filesystem from the same image the Docker sandbox would use** (`TestRunSpec.image`):
   `docker create` + `docker export`, unpacked without device nodes or ownership, plus this
   module's init script and the command, then `mkfs.ext4 -d` into an image file.
2. **The checkout as a second disk**, also `mkfs.ext4 -d`, writable (tests write caches) and
   thrown away after the run. This is ADR-0031's "bake it in per run" choice: no virtiofs daemon,
   no network into the guest.
3. **No network interface at all** -- stricter than the Docker sandbox's deny-internal posture, so
   dependencies must already be in the image; a command that runs `pip install` fails here.
4. **The guest's init** mounts the disks, runs the command with `sh -c`, then kills every other
   process, prints the exit code on the serial console, and reboots, which ends the VM.
   The result is the last marker line, which nothing but init can print once every other process
   is dead. (A hostile test suite can still "pass" by exiting 0 -- as it can in Docker; the
   boundary here is about containment, not about trusting the result.)

Needs: Linux with `/dev/kvm` readable and writable by this user, a `firecracker` binary, an
uncompressed guest kernel (`vmlinux`), `mkfs.ext4` (e2fsprogs >= 1.43, for `-d`) and Docker (to
read the image). `check_host` says which is missing. For production, run Firecracker through its
`jailer` (chroot, cgroups, a dedicated uid) as Firecracker's own docs recommend; this module runs
the `firecracker` binary directly, which still applies Firecracker's built-in seccomp filters.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from core.config import scratch_dir

INIT_PATH = "/bulwark-init"
COMMAND_PATH = "/bulwark-command"
EXIT_MARKER = "BULWARK-EXIT"
BOOT_ARGS = f"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init={INIT_PATH}"
ROOTFS_HEADROOM_MIB = 512
WORK_HEADROOM_MIB = 1024
_MARKER = re.compile(rf"^{EXIT_MARKER} (-?\d+)\s*$", re.MULTILINE)

# The guest's PID 1. Plain POSIX sh plus `mount`, which every Debian/Alpine/Ubuntu base image has.
# `kill -9 -1` from PID 1 kills every other process, so nothing the test suite left behind can
# print after the marker, or keep the VM up. It ends with a reboot, not a power-off: Firecracker
# on x86 cannot power a guest off, and a reboot (`reboot=k`) is what makes it exit on both x86
# and Arm.
INIT_SCRIPT = f"""#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp
mkdir -p /work
mount /dev/vdb /work
cd /work
export HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
sh -c "$(cat {COMMAND_PATH})"
code=$?
kill -9 -1 2>/dev/null
sync
echo "{EXIT_MARKER} $code"
echo 1 > /proc/sys/kernel/sysrq
echo b > /proc/sysrq-trigger
"""


class FirecrackerError(Exception):
    """The host cannot run a microVM, or one could not be prepared: an environment problem, never
    a test outcome."""


@dataclass(frozen=True)
class FirecrackerConfig:
    kernel: Path
    firecracker: str = "firecracker"
    kvm: Path = field(default=Path("/dev/kvm"))

    @staticmethod
    def from_env() -> FirecrackerConfig:
        """`BULWARK_FIRECRACKER_KERNEL` (required) and `BULWARK_FIRECRACKER_BIN`."""
        kernel = os.environ.get("BULWARK_FIRECRACKER_KERNEL", "")
        if not kernel:
            raise FirecrackerError("BULWARK_FIRECRACKER_KERNEL is not set (a guest vmlinux path)")
        return FirecrackerConfig(
            kernel=Path(kernel),
            firecracker=os.environ.get("BULWARK_FIRECRACKER_BIN", "firecracker"),
        )


def check_host(cfg: FirecrackerConfig) -> None:
    """Raises FirecrackerError naming the first thing missing."""
    if not cfg.kvm.exists():
        raise FirecrackerError(f"{cfg.kvm} does not exist: this host has no KVM")
    if not os.access(cfg.kvm, os.R_OK | os.W_OK):
        raise FirecrackerError(f"{cfg.kvm} is not readable and writable by this user")
    if shutil.which(cfg.firecracker) is None:
        raise FirecrackerError(f"{cfg.firecracker!r} is not installed or not on PATH")
    if not cfg.kernel.is_file():
        raise FirecrackerError(f"guest kernel {cfg.kernel} does not exist")
    for tool in ("mkfs.ext4", "docker"):
        if shutil.which(tool) is None:
            raise FirecrackerError(f"{tool} is not installed or not on PATH")


def memory_mib(memory: str) -> int:
    """Docker's notation ("2g", "512m", "1024k", bytes) in MiB, rounded up, at least 128."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgKMG]?)[bB]?\s*", memory)
    if m is None:
        raise ValueError(f"not a memory size: {memory!r}")
    value, unit = float(m.group(1)), m.group(2).lower()
    mib = {"g": value * 1024, "m": value, "k": value / 1024, "": value / (1024 * 1024)}[unit]
    return max(128, math.ceil(mib))


def vm_config(
    cfg: FirecrackerConfig, rootfs: Path, work: Path, *, vcpus: int, mem_mib: int
) -> dict[str, object]:
    """Firecracker's `--config-file` document: the kernel, the two disks, the machine, and no
    network interface."""
    return {
        "boot-source": {"kernel_image_path": str(cfg.kernel), "boot_args": BOOT_ARGS},
        "drives": [
            {"drive_id": "rootfs", "path_on_host": str(rootfs), "is_root_device": True,
             "is_read_only": False},
            {"drive_id": "work", "path_on_host": str(work), "is_root_device": False,
             "is_read_only": False},
        ],
        "machine-config": {"vcpu_count": vcpus, "mem_size_mib": mem_mib},
        "network-interfaces": [],
    }  # fmt: skip


def exit_code(console: str) -> int | None:
    """The code init printed last, or None when the guest never got that far (it crashed, ran
    out of memory, or the kernel could not boot)."""
    found = _MARKER.findall(console)
    return int(found[-1]) if found else None


def _tree_mib(path: Path) -> int:
    total = sum(p.lstat().st_size for p in path.rglob("*") if not p.is_symlink() and p.is_file())
    return math.ceil(total / (1024 * 1024))


def _mkfs(source: Path, image: Path, size_mib: int) -> None:
    proc = subprocess.run(
        ["mkfs.ext4", "-q", "-F", "-d", str(source), str(image), f"{size_mib}M"],
        capture_output=True, check=False,
    )  # fmt: skip
    if proc.returncode != 0:
        raise FirecrackerError(f"mkfs.ext4 failed: {proc.stderr.decode(errors='replace')[-500:]}")


def _inside(root: str, path: str) -> bool:
    return path == root or path.startswith(root + os.sep)


def _unpack(tar_path: Path, dest: Path) -> None:
    """The image's files, without device nodes, FIFOs, ownership or setuid bits (an unprivileged
    user can create none of them, and the guest needs none), and nothing written outside `dest`.

    Not tarfile's extraction filters: they need Python 3.10.12+, and the "data" filter refuses
    absolute symlinks, which every Debian image has (python:3.12-slim: 187). An absolute link is
    harmless as a link -- it resolves inside the guest -- so links are kept as written, and what is
    checked is where each member would actually be written on this host: its parent directory,
    with every link already unpacked followed, must still be inside `dest`, and an existing link at
    its own name is removed first rather than written through."""
    root = os.path.realpath(dest)
    with tarfile.open(tar_path) as tar:
        for m in tar:
            if not (m.isreg() or m.isdir() or m.issym() or m.islnk()):
                continue
            target = os.path.join(root, m.name.lstrip("/"))
            if not _inside(root, os.path.realpath(os.path.dirname(target))):
                continue
            if m.islnk():
                linked = os.path.realpath(os.path.join(root, m.linkname.lstrip("/")))
                if not _inside(root, linked):
                    continue
                m.linkname = m.linkname.lstrip("/")
            if os.path.islink(target) or (os.path.lexists(target) and not m.isdir()):
                os.unlink(target)
            m.mode = 0o755 if m.isdir() else (m.mode & 0o755) | 0o600
            m.uid = m.gid = os.getuid()
            tar.extract(m, root)


def build_rootfs(image: str, command: str, dest: Path, workdir: Path) -> None:
    """`image`'s filesystem, plus the init script and the command, as an ext4 image at `dest`."""
    created = subprocess.run(["docker", "create", image, "true"], capture_output=True, check=False)
    if created.returncode != 0:
        raise FirecrackerError(
            f"cannot read image {image!r}: {created.stderr.decode(errors='replace')[-500:]}"
        )
    cid = created.stdout.decode().strip()
    tar_path = workdir / "image.tar"
    try:
        with tar_path.open("wb") as out:
            exported = subprocess.run(["docker", "export", cid], stdout=out, check=False)
        if exported.returncode != 0:
            raise FirecrackerError(f"docker export of {image!r} failed")
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, check=False)
    tree = workdir / "rootfs"
    tree.mkdir()
    _unpack(tar_path, tree)
    tar_path.unlink()
    for d in ("proc", "sys", "dev", "tmp", "work"):
        (tree / d).mkdir(exist_ok=True)
    init = tree / INIT_PATH.lstrip("/")
    init.write_text(INIT_SCRIPT)
    init.chmod(0o755)
    (tree / COMMAND_PATH.lstrip("/")).write_text(command)
    _mkfs(tree, dest, _tree_mib(tree) + ROOTFS_HEADROOM_MIB)
    shutil.rmtree(tree, ignore_errors=True)


def build_work_disk(checkout: Path, dest: Path) -> None:
    _mkfs(checkout, dest, _tree_mib(checkout) + WORK_HEADROOM_MIB)


@dataclass(frozen=True)
class MicroVMResult:
    exit_code: int | None  # None: the guest never reported one
    console: str
    timed_out: bool = False


def run_in_microvm(
    cfg: FirecrackerConfig,
    checkout: Path,
    image: str,
    command: str,
    *,
    vcpus: int,
    mem_mib: int,
    timeout_s: int,
) -> MicroVMResult:
    """Boots a microVM that runs `command` in a copy of `checkout`, and returns what it printed and
    the code it exited with. Raises FirecrackerError for an environment problem."""
    check_host(cfg)
    with tempfile.TemporaryDirectory(prefix="bulwark-fc-", dir=scratch_dir()) as tmp:
        workdir = Path(tmp)
        rootfs, work = workdir / "rootfs.ext4", workdir / "work.ext4"
        build_rootfs(image, command, rootfs, workdir)
        build_work_disk(checkout, work)
        config = workdir / "vm.json"
        config.write_text(json.dumps(vm_config(cfg, rootfs, work, vcpus=vcpus, mem_mib=mem_mib)))
        argv = [cfg.firecracker, "--no-api", "--config-file", str(config)]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:  # subprocess.run kills the process itself
            out = (exc.stdout or b"").decode("utf-8", errors="replace")
            return MicroVMResult(None, out, timed_out=True)
        console = proc.stdout.decode("utf-8", errors="replace")
        return MicroVMResult(exit_code(console), console)
