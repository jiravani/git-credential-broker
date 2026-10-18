"""Live policy loading and atomic owner updates; no agent-selected policy path."""

import fcntl
import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from .errors import Denied
from .files import atomic_write, read_file
from .models import BrokerConfig


class PolicySource(Protocol):
    """A trusted source of a complete, validated standing policy."""

    def load(self) -> BrokerConfig:
        """Load current policy; failures must deny writes."""
        ...


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_config(raw: bytes) -> BrokerConfig:
    """Parse strict JSON, including rejection of duplicate fields and invalid numbers."""
    try:
        value = json.loads(raw, object_pairs_hook=_unique_fields)
        return BrokerConfig.model_validate(value)
    except (ValueError, ValidationError, RecursionError):
        raise Denied("invalid policy document") from None


class FilePolicy:
    """Read an owner-selected file for every grant and dispatch."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()

    def load(self) -> BrokerConfig:
        """Reject unsafe file modes before interpreting policy."""
        return parse_config(read_file(self.path, 1024 * 1024, secret=False))

    def apply(self, raw: bytes, state_root: Path) -> str:
        """Apply a validated revision under the same lock used for dispatch."""
        policy = parse_config(raw)
        with dispatch_lock(state_root):
            atomic_write(self.path, policy.model_dump_json(indent=2).encode())
        return policy.revision()


@contextmanager
def dispatch_lock(root: Path) -> Iterator[None]:
    """Serialize dispatch and owner policy changes across service processes."""
    fd = os.open(root / "dispatch.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Denied("unsafe dispatch lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)
