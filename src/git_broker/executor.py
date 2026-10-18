"""Hermetic Git write executor with pinned destinations and exact-tip leases.

Git is a native parser, not a sandbox. Deploy this service under a separate UID
with Linux process/filesystem isolation and aggregate disk/network quotas.
"""

import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit

from .errors import Denied, ExecutionError
from .models import OperationPlan, Repository, matches


@dataclass(frozen=True)
class Credential:
    """Upstream credential material; never render its value in diagnostics."""

    value: bytes = field(repr=False)
    kind: Literal["https", "ssh"]


class Executor(Protocol):
    """Trusted, replaceable execution boundary used after capability reservation."""

    def execute(
        self, repository: Repository, plan: OperationPlan, payload: bytes,
        credential: Credential | None,
    ) -> dict[str, object]:
        """Execute exactly the authorized plan or raise a safe public error."""
        ...


def _private_directory(path: Path) -> None:
    """Create or validate a broker-owned directory without following symlinks."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Denied("executor directory is not private")
    for parent in path.absolute().parents:
        if parent.is_symlink():
            raise Denied("executor directory has a symlink ancestor")


def _write_private(path: Path, data: bytes) -> None:
    """Exclusively create and durably write a private regular file."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class GitExecutor:
    """Perform fixed Git operations in new broker-owned bare repositories."""

    def __init__(
        self, root: Path, allow_local_test: bool = False, max_bundle_bytes: int = 8388608,
    ) -> None:
        """Configure private work storage and an explicit disposable-test escape hatch."""
        self.root = root.absolute()
        self.allow_local_test = allow_local_test
        self.max_bundle_bytes = max_bundle_bytes
        _private_directory(self.root)

    def _remote(self, repo: Repository) -> str:
        """Reject ambiguous URLs, shell syntax, helper protocols and noncanonical paths."""
        if repo.backend == "local_test":
            if not self.allow_local_test or not Path(repo.remote).is_absolute():
                raise Denied("local transport is disabled")
            return repo.remote
        if not repo.remote.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in repo.remote):
            raise Denied("invalid destination")
        try:
            url = urlsplit(repo.remote)
            port = url.port
        except ValueError:
            raise Denied("invalid destination") from None
        if (
            url.scheme != repo.backend or not url.hostname
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", url.hostname)
            or url.query or url.fragment or url.password is not None
            or not re.fullmatch(r"/[A-Za-z0-9_./-]+\.git", url.path)
            or any(part in {"", ".", ".."} for part in url.path.split("/")[1:])
            or (port is not None and not 1 <= port <= 65535)
            or (repo.backend == "https" and url.username is not None)
            or (repo.backend == "ssh" and (
                url.username is None or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", url.username)
            ))
        ):
            raise Denied("invalid destination")
        return repo.remote

    def _environment(
        self, repo: Repository, directory: Path, credential: Credential | None,
    ) -> dict[str, str]:
        """Construct a clean environment with broker-only transport authentication."""
        env = {
            "PATH": "/usr/bin:/bin", "HOME": str(directory), "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ATTR_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": "file" if repo.backend == "local_test" else repo.backend,
        }
        if repo.backend == "local_test":
            if credential is not None:
                raise Denied("test transport does not accept credentials")
            return env
        if credential is None or credential.kind != repo.backend:
            raise Denied("matching upstream credential is required")
        secret = directory / "credential"
        _write_private(secret, credential.value)
        if repo.backend == "https":
            if not credential.value or b"\n" in credential.value or b"\x00" in credential.value:
                raise Denied("invalid HTTP credential")
            helper = directory / "askpass"
            _write_private(helper, b'#!/bin/sh\ncase "$1" in *Password*) /bin/cat "$BROKER_SECRET";; *) exit 1;; esac\n')
            helper.chmod(0o700)
            env.update(GIT_ASKPASS=str(helper), BROKER_SECRET=str(secret))
        else:
            known = Path(repo.known_hosts)
            if not known.is_absolute() or known.is_symlink() or not known.is_file():
                raise Denied("trusted SSH host keys are required")
            info = known.stat()
            if info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
                raise Denied("SSH host key file is not trusted")
            pinned = directory / "known_hosts"
            _write_private(pinned, known.read_bytes())
            env["GIT_SSH_COMMAND"] = shlex.join([
                "/usr/bin/ssh", "-F", "/dev/null", "-i", str(secret),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "IdentityAgent=none", "-o", "ForwardAgent=no",
                "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", f"UserKnownHostsFile={pinned}", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "ConnectTimeout=10",
            ])
            env["GIT_SSH_VARIANT"] = "ssh"
        return env

    def _run(
        self, directory: Path, env: dict[str, str], args: list[str], *, accept: tuple[int, ...] = (0,),
    ) -> bytes:
        """Bound output, runtime and native resources; never expose subprocess diagnostics."""
        command = [
            sys.executable, "-I", str(Path(__file__).with_name("git_limits.py")),
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "credential.helper=", "-c", "http.followRedirects=false",
            "-c", "http.sslVerify=true", "-c", "fetch.fsckObjects=true",
            "-c", "receive.fsckObjects=true", "-c", "transfer.fsckObjects=true",
            "-c", "protocol.version=2", *args,
        ]
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                command, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.DEVNULL, start_new_session=True,
            )
            try:
                status = process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ExecutionError("Git operation timed out; outcome may be unknown") from None
            if status not in accept or output.tell() > 1024 * 1024:
                raise ExecutionError("Git operation failed; outcome may be unknown")
            output.seek(0)
            return output.read(1024 * 1024)

    def execute(
        self, repository: Repository, plan: OperationPlan, payload: bytes,
        credential: Credential | None,
    ) -> dict[str, object]:
        """Execute one read, fast-forward push, or recoverable exact-tip deletion."""
        try:
            return self._execute(repository, plan, payload, credential)
        except (OSError, UnicodeError, ValueError):
            raise ExecutionError("Git execution environment failed") from None

    def _execute(
        self, repository: Repository, plan: OperationPlan, payload: bytes,
        credential: Credential | None,
    ) -> dict[str, object]:
        """Apply defensive validation independently of caller policy checks."""
        remote = self._remote(repository)
        if plan.operation != "read" and (
            plan.branch == repository.default_branch or matches(plan.branch, repository.protected)
            or not repository.automation_reviewed
        ):
            raise Denied("repository or branch is not eligible for writes")
        if len(payload) > self.max_bundle_bytes:
            raise Denied("bundle exceeds size limit")
        if plan.operation != "push" and payload:
            raise Denied("unexpected payload")
        if plan.operation == "push" and hashlib.sha256(payload).hexdigest() != plan.payload_digest:
            raise Denied("payload digest mismatch")
        with tempfile.TemporaryDirectory(prefix="operation-", dir=self.root) as tmp:
            directory = Path(tmp)
            transport_env = self._environment(repository, directory, credential)
            env = {key: value for key, value in transport_env.items()
                   if key not in {"GIT_ASKPASS", "BROKER_SECRET", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT"}}
            env["GIT_ALLOW_PROTOCOL"] = "file"
            args = ["-c", f"credential.username={repository.username}"]
            self._run(directory, env, ["init", "--bare", "--template=", "repo"])
            gitdir = directory / "repo"
            ref = f"refs/heads/{plan.branch}"
            tip_data = self._run(gitdir, transport_env, [*args, "ls-remote", "--refs", remote, ref])
            tip = ""
            if tip_data:
                line = tip_data.decode("ascii").strip().split("\t")
                if len(line) != 2 or line[1] != ref or not re.fullmatch(r"[0-9a-f]{40}", line[0]):
                    raise Denied("invalid remote reference advertisement")
                tip = line[0]
            if plan.operation == "read":
                return {"repository": plan.repository, "branch": plan.branch, "commit": tip}
            if tip != plan.expected_old:
                raise Denied("remote branch has changed")
            if tip:
                self._run(gitdir, transport_env, [*args, "fetch", "--no-tags", "--no-recurse-submodules",
                                        remote, f"{ref}:refs/heads/broker-old"])
                fetched = self._run(gitdir, env, ["rev-parse", "refs/heads/broker-old"]).strip()
                if fetched.decode("ascii") != tip:
                    raise Denied("remote branch changed during fetch")
            if plan.operation == "delete":
                handle = self._backup(gitdir, env, plan)
                self._run(gitdir, transport_env, [*args, "push", "--porcelain",
                                        f"--force-with-lease={ref}:{tip}", remote, f":{ref}"])
                return {"repository": plan.repository, "branch": plan.branch,
                        "deleted": True, "backup": handle}
            bundle = directory / "payload.bundle"
            _write_private(bundle, payload)
            heads = self._run(gitdir, env, ["bundle", "list-heads", str(bundle)])
            if heads != f"{plan.commit} HEAD\n".encode("ascii"):
                raise Denied("bundle must advertise exactly the planned HEAD")
            # Verify in a fresh empty repository BEFORE importing remote objects so
            # prerequisite bundles cannot smuggle dependencies from the destination.
            self._run(directory, env, ["init", "--bare", "--template=", "verify"])
            self._run(directory / "verify", env, ["bundle", "verify", str(bundle)])
            self._run(gitdir, env, ["fetch", "--no-tags", str(bundle), "HEAD:refs/heads/broker-new"])
            self._run(gitdir, env, ["fsck", "--strict", "--no-reflogs"])
            kind = self._run(gitdir, env, ["cat-file", "-t", plan.commit]).strip()
            if kind != b"commit":
                raise Denied("planned object is not a commit")
            if tip:
                self._run(gitdir, env, ["merge-base", "--is-ancestor", tip, plan.commit])
            self._run(gitdir, transport_env, [*args, "push", "--porcelain",
                                    f"--force-with-lease={ref}:{tip}", remote,
                                    f"{plan.commit}:{ref}"])
            return {"repository": plan.repository, "branch": plan.branch, "commit": plan.commit}

    def _backup(self, gitdir: Path, env: dict[str, str], plan: OperationPlan) -> str:
        """Durably preserve full deleted history and recovery metadata before mutation."""
        recovery = self.root / "recovery"
        _private_directory(recovery)
        handle = uuid.uuid4().hex
        target = recovery / handle
        target.mkdir(mode=0o700)
        bundle = target / "history.bundle"
        self._run(gitdir, env, ["fsck", "--strict", "--no-reflogs"])
        self._run(gitdir, env, ["bundle", "create", str(bundle), "refs/heads/broker-old"])
        with tempfile.TemporaryDirectory(prefix="verify-backup-", dir=self.root) as check:
            checkdir = Path(check)
            self._run(checkdir, env, ["init", "--bare", "--template=", "."])
            self._run(checkdir, env, ["bundle", "verify", str(bundle)])
        bundle.chmod(0o600)
        with bundle.open("rb") as stream:
            os.fsync(stream.fileno())
        _write_private(target / "metadata.json", json.dumps(plan.model_dump()).encode())
        for path in (target, recovery):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return handle
