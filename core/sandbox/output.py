"""Reading a file a container wrote into a directory shared with the host.

The scanner's output directory is the one path a sandboxed container can write that this process
then reads, so what is there is the container's word, not ours: a scanner that a hostile repository
has taken over can leave anything in it. Three things a plain `path.read_bytes()` gets wrong:

- **a symbolic link** is followed on the host, in the host's file system: `result.json ->
  /proc/self/environ` would be read as the scanner's "output", with this process's secrets in it;
- **a FIFO** blocks the open for ever (nobody writes to it), and with it the worker;
- **a file of any size** is read whole into memory.

So: the name itself is opened (never what it points to), without blocking; it must be a regular
file; and it may be at most `max_bytes`.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

#: Far above any real report (the largest seen, Trivy on a monorepo, are tens of megabytes).
MAX_OUTPUT_BYTES = 512 * 1024 * 1024


class OutputRefused(Exception):
    """What the container left is not something to read: a link, a device, or too large."""


def read_output(path: Path, max_bytes: int = MAX_OUTPUT_BYTES) -> bytes | None:
    """The bytes of the regular file at `path`, or None when there is nothing there."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):  # what O_NOFOLLOW answers for a link
            raise OutputRefused(f"{path.name} is a symbolic link, not a file") from exc
        raise OutputRefused(f"{path.name} could not be opened ({exc.strerror})") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OutputRefused(f"{path.name} is not a regular file")
        if info.st_size > max_bytes:
            raise OutputRefused(f"{path.name} is larger than {max_bytes} bytes")
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(max_bytes + 1)  # the size can change after fstat; this cannot be passed
    if len(data) > max_bytes:
        raise OutputRefused(f"{path.name} is larger than {max_bytes} bytes")
    return data
