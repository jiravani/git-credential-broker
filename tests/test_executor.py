"""Adversarial disposable-repository tests; no provider credentials or remote writes."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from git_broker.errors import Denied, ExecutionError
from git_broker.executor import Credential, GitExecutor
from git_broker.models import OperationPlan, Repository


def git(path: Path, *args: str) -> str:
    """Run fixture-only Git commands with deterministic author metadata."""
    result = subprocess.run(
        ["/usr/bin/git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
        cwd=path, check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
    )
    return result.stdout.strip()


@pytest.fixture
def setup(tmp_path: Path) -> tuple[GitExecutor, Repository, Path, Path]:
    """Create empty trusted remote and disposable untrusted client repository."""
    remote = tmp_path / "remote.git"
    work = tmp_path / "client"
    remote.mkdir()
    work.mkdir()
    git(remote, "init", "--bare")
    git(work, "init", "-b", "feature")
    git(work, "commit", "--allow-empty", "-m", "first")
    repo = Repository(backend="local_test", remote=str(remote), automation_reviewed=True)
    return GitExecutor(tmp_path / "broker", allow_local_test=True), repo, work, remote


def push_plan(work: Path, branch: str = "feature", old: str = "") -> tuple[OperationPlan, bytes]:
    """Produce a self-contained bundle with exactly HEAD advertised."""
    bundle = work / "bundle"
    bundle.unlink(missing_ok=True)
    git(work, "bundle", "create", str(bundle), "HEAD")
    payload = bundle.read_bytes()
    return OperationPlan(
        operation="push", repository="test", branch=branch, expected_old=old,
        commit=git(work, "rev-parse", "HEAD"), payload_digest=hashlib.sha256(payload).hexdigest(),
    ), payload


def test_create_read_fast_forward(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, remote = setup
    plan, payload = push_plan(work)
    assert executor.execute(repo, plan, payload, None)["commit"] == plan.commit
    read = OperationPlan(operation="read", repository="test", branch="feature")
    assert executor.execute(repo, read, b"", None)["commit"] == plan.commit
    git(work, "commit", "--allow-empty", "-m", "second")
    next_plan, payload = push_plan(work, old=plan.commit)
    executor.execute(repo, next_plan, payload, None)
    assert git(remote, "rev-parse", "refs/heads/feature") == next_plan.commit


def test_non_fast_forward_and_stale_tip_denied(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, remote = setup
    original, payload = push_plan(work)
    executor.execute(repo, original, payload, None)
    git(work, "commit", "--allow-empty", "-m", "second")
    second, payload = push_plan(work, old=original.commit)
    executor.execute(repo, second, payload, None)
    git(work, "reset", "--hard", original.commit)
    rewind, payload = push_plan(work, old=second.commit)
    with pytest.raises(ExecutionError):
        executor.execute(repo, rewind, payload, None)
    stale, payload = push_plan(work, old=original.commit)
    with pytest.raises(Denied, match="changed"):
        executor.execute(repo, stale, payload, None)
    assert git(remote, "rev-parse", "refs/heads/feature") == second.commit


@pytest.mark.parametrize("branch", ["main", "master", "release/v1"])
def test_protected_branches(setup: tuple[GitExecutor, Repository, Path, Path], branch: str) -> None:
    executor, repo, work, remote = setup
    plan, payload = push_plan(work, branch)
    with pytest.raises(Denied):
        executor.execute(repo, plan, payload, None)
    assert not git(remote, "for-each-ref")


def test_payload_tamper_size_and_extra_heads(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, _ = setup
    plan, payload = push_plan(work)
    with pytest.raises(Denied, match="digest"):
        executor.execute(repo, plan, payload + b"bad", None)
    executor.max_bundle_bytes = 1
    with pytest.raises(Denied, match="size"):
        executor.execute(repo, plan, payload, None)
    executor.max_bundle_bytes = 8388608
    git(work, "bundle", "create", str(work / "extra"), "HEAD", "feature")
    payload = (work / "extra").read_bytes()
    plan = plan.model_copy(update={"payload_digest": hashlib.sha256(payload).hexdigest()})
    with pytest.raises(Denied, match="exactly"):
        executor.execute(repo, plan, payload, None)


def test_prerequisite_bundle_rejected(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, remote = setup
    plan, payload = push_plan(work)
    executor.execute(repo, plan, payload, None)
    git(work, "commit", "--allow-empty", "-m", "second")
    git(work, "bundle", "create", str(work / "partial"), f"{plan.commit}..HEAD")
    payload = (work / "partial").read_bytes()
    partial = OperationPlan(operation="push", repository="test", branch="feature",
                            expected_old=plan.commit, commit=git(work, "rev-parse", "HEAD"),
                            payload_digest=hashlib.sha256(payload).hexdigest())
    with pytest.raises(ExecutionError):
        executor.execute(repo, partial, payload, None)
    assert git(remote, "rev-parse", "refs/heads/feature") == plan.commit


def test_deletion_has_recoverable_durable_history(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, remote = setup
    plan, payload = push_plan(work)
    executor.execute(repo, plan, payload, None)
    delete = OperationPlan(operation="delete", repository="test", branch="feature",
                           expected_old=plan.commit)
    result = executor.execute(repo, delete, b"", None)
    assert not git(remote, "for-each-ref")
    backup = executor.root / "recovery" / str(result["backup"])
    assert (backup.stat().st_mode & 0o777) == 0o700
    assert (backup / "history.bundle").stat().st_mode & 0o777 == 0o600
    assert json.loads((backup / "metadata.json").read_text())["expected_old"] == plan.commit
    git(work, "bundle", "verify", str(backup / "history.bundle"))
    git(remote, "fetch", str(backup / "history.bundle"), "refs/heads/broker-old:refs/heads/restored")
    assert git(remote, "rev-parse", "refs/heads/restored") == plan.commit


def test_failed_backup_prevents_deletion(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, remote = setup
    plan, payload = push_plan(work)
    executor.execute(repo, plan, payload, None)
    (executor.root / "recovery").symlink_to(work, target_is_directory=True)
    delete = OperationPlan(operation="delete", repository="test", branch="feature",
                           expected_old=plan.commit)
    with pytest.raises(Denied):
        executor.execute(repo, delete, b"", None)
    assert git(remote, "rev-parse", "refs/heads/feature") == plan.commit


@pytest.mark.parametrize("url", [
    "https://user:password@example.com/a.git", "https://example.com/a.git?x=1",
    "https://example.com/a.git#x", "https://example.com/../a.git",
    "https://example.com/a%20b.git", "https://example.com:99999/a.git",
    "https://example.com/a.git\n", "https://example.com//a.git",
    "ssh://git@example.com/a;touch.git", "ssh://-oProxyCommand@example.com/a.git",
    "ext::sh -c evil", "file:///tmp/test.git",
])
def test_bad_destinations(tmp_path: Path, url: str) -> None:
    executor = GitExecutor(tmp_path / "broker")
    repo = Repository(backend="ssh" if url.startswith("ssh") else "https", remote=url)
    with pytest.raises(Denied):
        executor.execute(repo, OperationPlan(operation="read", repository="test", branch="feature"),
                         b"", None)


def test_production_local_transport_disabled(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, _ = setup
    executor.allow_local_test = False
    plan, payload = push_plan(work)
    with pytest.raises(Denied):
        executor.execute(repo, plan, payload, None)


def test_ambient_git_config_and_hooks_ignored(
    setup: tuple[GitExecutor, Repository, Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, repo, work, _ = setup
    marker = work / "pwned"
    hooks = work / "hooks"
    hooks.mkdir()
    hook = hooks / "pre-push"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    hook.chmod(0o700)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(hooks))
    monkeypatch.setenv("GIT_SSH_COMMAND", "exit 1")
    plan, payload = push_plan(work)
    executor.execute(repo, plan, payload, None)
    assert not marker.exists()


def test_credentials_redacted_and_workspace_private(tmp_path: Path) -> None:
    assert "super-secret" not in repr(Credential(b"super-secret", "https"))
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(Denied):
        GitExecutor(public)
    target = tmp_path / "private"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(Denied):
        GitExecutor(link)


def test_remote_race_rejected_by_lease(
    setup: tuple[GitExecutor, Repository, Path, Path], monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, repo, work, remote = setup
    original, payload = push_plan(work)
    executor.execute(repo, original, payload, None)
    git(work, "commit", "--allow-empty", "-m", "next")
    next_plan, payload = push_plan(work, old=original.commit)
    git(work, "push", str(remote), "HEAD:refs/heads/other")
    third = git(work, "rev-parse", "HEAD")
    run = executor._run

    def racing_run(
        directory: Path, env: dict[str, str], args: list[str], *, accept: tuple[int, ...] = (0,),
    ) -> bytes:
        if "push" in args:
            git(remote, "update-ref", "refs/heads/feature", third)
        return run(directory, env, args, accept=accept)

    monkeypatch.setattr(executor, "_run", racing_run)
    # Git permits an already-up-to-date update despite the stale lease. Use a
    # distinct remote commit so this exercises a real conflicting ref mutation.
    git(work, "commit", "--allow-empty", "-m", "conflict")
    git(work, "push", str(remote), "HEAD:refs/heads/other")
    third = git(work, "rev-parse", "HEAD")
    with pytest.raises(ExecutionError):
        executor.execute(repo, next_plan, payload, None)
    assert git(remote, "rev-parse", "refs/heads/feature") == third


def test_corrupt_pack_denied(setup: tuple[GitExecutor, Repository, Path, Path]) -> None:
    executor, repo, work, remote = setup
    plan, payload = push_plan(work)
    corrupt = payload[:-10] + b"brokenpack"
    plan = plan.model_copy(update={"payload_digest": hashlib.sha256(corrupt).hexdigest()})
    with pytest.raises(ExecutionError):
        executor.execute(repo, plan, corrupt, None)
    assert not git(remote, "for-each-ref")


def test_secure_transport_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executor = GitExecutor(tmp_path / "broker")
    scratch = executor.root / "scratch"
    scratch.mkdir(mode=0o700)
    known = tmp_path / "hosts"
    known.write_text("example.invalid ssh-ed25519 AAAATEST\n")
    known.chmod(0o600)
    monkeypatch.setenv("SSH_AUTH_SOCK", "/evil/agent")
    monkeypatch.setenv("GIT_SSL_NO_VERIFY", "true")
    repo = Repository(backend="ssh", remote="ssh://git@example.invalid/project.git", known_hosts=str(known))
    env = executor._environment(repo, scratch, Credential(b"private key", "ssh"))
    assert "SSH_AUTH_SOCK" not in env
    assert "GIT_SSL_NO_VERIFY" not in env
    assert "StrictHostKeyChecking=yes" in env["GIT_SSH_COMMAND"]
    assert "IdentityAgent=none" in env["GIT_SSH_COMMAND"]
    assert "private key" not in str(env)
    assert (scratch / "credential").stat().st_mode & 0o777 == 0o600
