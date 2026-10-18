"""Private, bounded file operations for owner-controlled service state."""

import os
import stat
import tempfile
from pathlib import Path

from .errors import Denied


def private_directory(path: Path) -> Path:
    """Create a private directory without accepting an existing symlink or loose mode."""
    path = path.absolute()
    if path.is_symlink():
        raise Denied("private directory cannot be a symbolic link")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISDIR(info.st_mode):
        raise Denied("private directory must be owned by the service with mode 0700")
    return path


def read_file(path: Path, limit: int, *, secret: bool = True) -> bytes:
    """Read a bounded, regular, non-symlink file with trusted ownership and mode."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            denied_bits = 0o077 if secret else 0o022
            owners = {os.getuid()} if secret else {os.getuid(), 0}
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in owners
                or info.st_mode & denied_bits
                or info.st_nlink != 1
                or info.st_size > limit
            ):
                raise Denied("unsafe file permissions, type, or size")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise Denied("file exceeds configured limit")
            return data
    except OSError:
        raise Denied("protected file is unavailable") from None


def atomic_write(path: Path, value: bytes, *, replace: bool = True) -> None:
    """Durably publish an owner-only file, refusing symlink destinations."""
    if path.is_symlink():
        raise Denied("destination cannot be a symbolic link")
    fd, temporary = tempfile.mkstemp(prefix=".broker-", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary_path, path)
        else:
            os.link(temporary_path, path)
            temporary_path.unlink()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary_path.unlink(missing_ok=True)
