"""Reads the staged (index) content of files about to be committed -- not the working tree.

A file can be `git add`ed and then edited further before `git commit` runs; the pre-commit hook
must see exactly what will land in the commit, which is the index blob (`:<path>`), not
`path.read_text()` (today's working-tree content, which may include unstaged edits the commit will
never contain -- or may be missing entirely for a staged deletion-then-recreate).

`load_staged_files` reads every blob with a single `git cat-file --batch` call rather than one
`git show` per file: on a 241-file real commit (this project's own `core/` tree) that cut the
hook's wall-clock time roughly tenfold (subprocess start-up, not the scan itself, was the cost) --
the gap between "comfortably under the 2-second budget" and "right at the edge of it" on a large
commit.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

# A watchdog per git invocation: these are local, already-checked-out operations against the
# index -- anything this slow indicates a hung process, not a big repo (plan §23's 2-second hook
# budget has no room for a single git call to run away).
_GIT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class StagedFile:
    path: str  # repo-relative, as git reports it
    text: str | None  # None when the blob isn't valid UTF-8 (treated as binary -- not scanned)


def _git(repo_dir: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        capture_output=True,
        timeout=_GIT_TIMEOUT_SECONDS,
        check=True,
    )
    return proc.stdout.decode("utf-8", errors="replace")


def list_staged_paths(repo_dir: Path) -> list[str]:
    """Added/Copied/Modified/Renamed paths in the index vs. HEAD. Deletions are excluded -- a
    deleted file has nothing left to scan."""
    out = _git(repo_dir, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [line for line in out.splitlines() if line]


def read_staged_blob(repo_dir: Path, rel_path: str) -> str | None:
    """A single file's content as staged (`git show :path`), or None if it isn't valid UTF-8
    text. `load_staged_files` is the fast path for "every staged file" -- this exists for callers
    that already know the one path they want."""
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "show", f":{rel_path}"],
        capture_output=True,
        timeout=_GIT_TIMEOUT_SECONDS,
    )
    if proc.returncode != 0:
        return None
    try:
        return proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_blobs_batch(repo_dir: Path, paths: list[str]) -> dict[str, bytes | None]:
    """Reads every `:path` blob in one `git cat-file --batch` round trip. Its output is
    `<sha> <type> <size>\\n<size bytes of content>\\n` per object (or `<spec> missing\\n` for one
    that isn't), parsed by byte-exact size rather than by scanning for a delimiter, since binary
    content can legitimately contain newline bytes."""
    if not paths:
        return {}
    stdin_data = "".join(f":{p}\n" for p in paths).encode("utf-8")
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "cat-file", "--batch"],
        input=stdin_data,
        capture_output=True,
        timeout=_GIT_TIMEOUT_SECONDS,
    )
    out = proc.stdout
    result: dict[str, bytes | None] = {}
    pos = 0
    for path in paths:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode("utf-8", errors="replace").split()
        pos = nl + 1
        if header[-1] == "missing":
            result[path] = None
            continue
        size = int(header[-1])
        result[path] = out[pos : pos + size]
        pos += size + 1  # the batch format's own trailing newline after each object's content
    return result


def load_staged_files(repo_dir: Path) -> list[StagedFile]:
    paths = list_staged_paths(repo_dir)
    blobs = _read_blobs_batch(repo_dir, paths)
    out: list[StagedFile] = []
    for path in paths:
        raw = blobs.get(path)
        if raw is None:
            out.append(StagedFile(path, None))
            continue
        try:
            out.append(StagedFile(path, raw.decode("utf-8")))
        except UnicodeDecodeError:
            out.append(StagedFile(path, None))
    return out
