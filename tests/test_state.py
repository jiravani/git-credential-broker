"""Adversarial capability accounting and durable execution tests."""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from git_broker.errors import Denied
from git_broker.models import OperationPlan
from git_broker.state import State

REVISION = "a" * 64


def read_plan(branch: str = "feature/test") -> OperationPlan:
    """Build a harmless metadata plan for accounting tests."""
    return OperationPlan(operation="read", repository="sample", branch=branch)


def token(value: dict[str, object]) -> str:
    """Extract the typed bearer value from an issuance response."""
    result = value["token"]
    assert isinstance(result, str)
    return result


@pytest.fixture
def state(tmp_path: Path) -> State:
    """Create a separate broker state directory per test."""
    return State(tmp_path / "state")


def reserve(state: State, session: str, plan: OperationPlan | None = None) -> dict[str, object]:
    """Issue and spend one capability."""
    plan = plan or read_plan()
    grant = state.request_grant(session, plan, REVISION, 60)
    return state.begin(session, token(grant), plan, REVISION, "request")


def test_durable_intent_is_never_redispatched(state: State) -> None:
    """A crash after intent cannot permit a second execution."""
    session = token(state.issue_session("agent", 3600, 1))
    plan = read_plan()
    grant = token(state.request_grant(session, plan, REVISION, 30))
    first = state.begin(session, grant, plan, REVISION, "key")
    assert first["newly_reserved"] is True
    restarted = State(state.root)
    duplicate = restarted.begin(session, grant, plan, REVISION, "key")
    assert duplicate["newly_reserved"] is False
    assert duplicate["id"] == first["id"]
    assert duplicate["state"] == "reserved"
    assert restarted.authenticate(session)["remaining"] == 0
    assert restarted.get_operation(session, str(first["id"]))["state"] == "reserved"
    with pytest.raises(Denied):
        restarted.begin(session, grant, plan, REVISION, "another")


def test_idempotency_binds_grant_and_complete_plan(state: State) -> None:
    """A reused request key cannot smuggle another plan or capability."""
    session = token(state.issue_session("agent", 3600, 3))
    plan = read_plan()
    grant = token(state.request_grant(session, plan, REVISION, 30))
    alternative = token(state.request_grant(session, plan, REVISION, 30))
    state.begin(session, grant, plan, REVISION, "key")
    with pytest.raises(Denied):
        state.begin(session, grant, read_plan("feature/other"), REVISION, "key")
    with pytest.raises(Denied):
        state.begin(session, alternative, plan, REVISION, "key")
    assert state.authenticate(session)["remaining"] == 2


def test_atomic_single_use_grant_under_race(state: State) -> None:
    """Concurrent callers with different request IDs cannot double-spend."""
    session = token(state.issue_session("agent", 3600, 10))
    plan = read_plan()
    grant = token(state.request_grant(session, plan, REVISION, 30))
    barrier = Barrier(8)

    def execute(index: int) -> bool:
        barrier.wait()
        try:
            return bool(state.begin(session, grant, plan, REVISION, f"key-{index}"))
        except Denied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(execute, range(8)))
    assert sum(outcomes) == 1
    assert state.authenticate(session)["remaining"] == 9


def test_atomic_budget_across_independent_grants(state: State) -> None:
    """Multiple grants cannot overdraw the session's last use."""
    session = token(state.issue_session("agent", 3600, 1))
    plan = read_plan()
    grants = [token(state.request_grant(session, plan, REVISION, 30)) for _ in range(8)]
    barrier = Barrier(8)

    def execute(index: int) -> bool:
        barrier.wait()
        try:
            state.begin(session, grants[index], plan, REVISION, f"key-{index}")
            return True
        except Denied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(execute, range(8))) == 1
    assert state.authenticate(session)["remaining"] == 0


def test_concurrent_idempotent_call_has_one_dispatch(state: State) -> None:
    """Duplicate HTTP retries see one reservation, not multiple dispatch permits."""
    session = token(state.issue_session("agent", 3600, 3))
    plan = read_plan()
    grant = token(state.request_grant(session, plan, REVISION, 30))
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(lambda _: state.begin(session, grant, plan, REVISION, "same"), range(8))
        )
    assert sum(bool(item["newly_reserved"]) for item in outcomes) == 1
    assert len({str(item["id"]) for item in outcomes}) == 1


def test_expiry_budget_revocation_and_policy(
    state: State, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Check expiry exactly at its boundary and invalidate revoked sessions."""
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1000)
    issued = state.issue_session("agent", 10, 2)
    session = token(issued)
    plan = read_plan()
    grant = state.request_grant(session, plan, REVISION, 300)
    assert grant["expires"] == 1010
    with pytest.raises(Denied):
        state.begin(session, token(grant), plan, "b" * 64, "changed-policy")
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1010)
    with pytest.raises(Denied):
        state.authenticate(session)
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1005)
    assert state.revoke(str(issued["id"]))
    assert not state.revoke(str(issued["id"]))
    with pytest.raises(Denied):
        state.begin(session, token(grant), plan, REVISION, "revoked")


def test_grant_expiry_without_session_expiry(
    state: State, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An expired grant cannot reserve execution under a still-valid session."""
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1000)
    session = token(state.issue_session("agent", 1000, 2))
    plan = read_plan()
    grant = token(state.request_grant(session, plan, REVISION, 1))
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1001)
    with pytest.raises(Denied):
        state.begin(session, grant, plan, REVISION, "expired")
    assert state.authenticate(session)["remaining"] == 2


def test_cross_session_confusion_is_denied(state: State) -> None:
    """Even the same principal's second session cannot borrow grants/results."""
    first = token(state.issue_session("agent", 3600, 2))
    second = token(state.issue_session("agent", 3600, 2))
    plan = read_plan()
    grant = token(state.request_grant(first, plan, REVISION, 30))
    with pytest.raises(Denied):
        state.begin(second, grant, plan, REVISION, "key")
    operation = state.begin(first, grant, plan, REVISION, "key")
    with pytest.raises(Denied):
        state.get_operation(second, str(operation["id"]))
    with pytest.raises(Denied):
        state.authenticate(grant)
    with pytest.raises(Denied):
        state.begin(first, first, plan, REVISION, "bad-token-class")


def test_finish_is_terminal_and_failure_never_refunds(state: State) -> None:
    """Ambiguous outcomes consume budget and cannot be overwritten as success."""
    session = token(state.issue_session("agent", 3600, 1))
    operation = reserve(state, session)
    identifier = str(operation["id"])
    state.finish(identifier, None, False)
    state.finish(identifier, None, False)
    with pytest.raises(Denied):
        state.finish(identifier, {"ok": True}, True)
    assert State(state.root).get_operation(session, identifier)["state"] == "failed_or_unknown"
    assert state.authenticate(session)["remaining"] == 0
    assert [row["event"] for row in state.audit()].count("operation_failed_or_unknown") == 1


def test_success_result_is_durable(state: State) -> None:
    """Safe metadata results survive restart without exposing internal records."""
    session = token(state.issue_session("agent", 3600, 1))
    operation = reserve(state, session)
    result: dict[str, object] = {"commit": "a" * 40, "branch": "feature/test"}
    state.finish(str(operation["id"]), result, True)
    record = State(state.root).get_operation(session, str(operation["id"]))
    assert record["result"] == result
    assert record["state"] == "succeeded"


def test_outstanding_grants_are_bounded(state: State) -> None:
    """Do not allow unlimited live grant fan-out."""
    session = token(state.issue_session("agent", 3600, 100))
    for _ in range(64):
        state.request_grant(session, read_plan(), REVISION, 30)
    with pytest.raises(Denied):
        state.request_grant(session, read_plan(), REVISION, 30)


def test_private_files_and_no_bearer_tokens_at_rest(state: State) -> None:
    """Persistent data holds only random-token hashes and minimal audit records."""
    session = token(state.issue_session("agent", 3600, 2))
    grant = token(state.request_grant(session, read_plan(), REVISION, 30))
    state.begin(session, grant, read_plan(), REVISION, "key")
    assert state.root.stat().st_mode & 0o777 == 0o700
    for path in state.root.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        assert session.encode() not in path.read_bytes()
        assert grant.encode() not in path.read_bytes()
    assert session not in str(state.audit())
    assert grant not in str(state.audit())


@pytest.mark.parametrize("attack", ["root_symlink", "db_symlink", "db_hardlink", "mode"])
def test_unsafe_files_fail_closed(tmp_path: Path, attack: str) -> None:
    """Never follow attacker-created state aliases or repair unsafe permissions."""
    real = tmp_path / "real"
    state = State(real)
    if attack == "root_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(real, target_is_directory=True)
        with pytest.raises(Denied):
            State(alias)
    elif attack == "db_symlink":
        state.path.rename(real / "target")
        state.path.symlink_to(real / "target")
        with pytest.raises(Denied):
            State(real)
    elif attack == "db_hardlink":
        os.link(state.path, real / "alias")
        with pytest.raises(Denied):
            state.audit()
    else:
        state.path.chmod(0o644)
        with pytest.raises(Denied):
            State(real)


def test_journal_symlink_is_rejected(state: State, tmp_path: Path) -> None:
    """An attacker cannot redirect the rollback journal to another file."""
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    Path(str(state.path) + "-journal").symlink_to(victim)
    with pytest.raises(Denied):
        state.issue_session("agent", 30, 1)
    assert victim.read_text() == "unchanged"


@pytest.mark.parametrize("bad", ["", "x" * 10000, "' OR 1=1 --", "é" * 43, "a" * 43])
def test_forged_tokens_are_denied(state: State, bad: str) -> None:
    """Malformed and unknown bearer strings fail without changing accounting."""
    with pytest.raises(Denied):
        state.authenticate(bad)


def test_database_failure_rolls_back_budget_and_reservation(state: State) -> None:
    """Audit persistence failure must prevent execution and preserve atomicity."""
    session = token(state.issue_session("agent", 3600, 1))
    plan = read_plan()
    grant = token(state.request_grant(session, plan, REVISION, 30))
    with sqlite3.connect(state.path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON events "
            "BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
    with pytest.raises(Denied):
        state.begin(session, grant, plan, REVISION, "key")
    assert state.authenticate(session)["remaining"] == 1
    with sqlite3.connect(state.path) as connection:
        assert connection.execute("SELECT count(*) FROM operations").fetchone()[0] == 0
        assert connection.execute("SELECT spent FROM grants").fetchone()[0] == 0


def test_delete_tombstone_survives_failed_execution_and_restart(state: State) -> None:
    """Deletion cannot turn forbidden replacement history into branch creation."""
    session = token(state.issue_session("agent", 3600, 4))
    deletion = OperationPlan(
        operation="delete", repository="sample", branch="feature/test", expected_old="a" * 40
    )
    deletion_grant = token(state.request_grant(session, deletion, REVISION, 60))
    operation = state.begin(session, deletion_grant, deletion, REVISION, "delete")
    state.finish(str(operation["id"]), None, False)
    restarted = State(state.root)
    creation = OperationPlan(
        operation="push",
        repository="sample",
        branch="feature/test",
        commit="b" * 40,
        payload_digest="c" * 64,
    )
    grant = token(restarted.request_grant(session, creation, REVISION, 60))
    with pytest.raises(Denied, match="owner recovery"):
        restarted.begin(session, grant, creation, REVISION, "recreate")
    update = creation.model_copy(update={"expected_old": "a" * 40})
    update_grant = token(restarted.request_grant(session, update, REVISION, 60))
    assert restarted.begin(session, update_grant, update, REVISION, "update")["newly_reserved"]


def test_delete_tombstone_race_blocks_concurrent_recreation(state: State) -> None:
    """Concurrent creation reservations after a delete intent all fail closed."""
    session = token(state.issue_session("agent", 3600, 20))
    deletion = OperationPlan(
        operation="delete", repository="sample", branch="feature/test", expected_old="a" * 40
    )
    reserve(state, session, deletion)
    creation = OperationPlan(
        operation="push",
        repository="sample",
        branch="feature/test",
        commit="b" * 40,
        payload_digest="c" * 64,
    )
    grants = [token(state.request_grant(session, creation, REVISION, 30)) for _ in range(8)]

    def execute(index: int) -> bool:
        try:
            state.begin(session, grants[index], creation, REVISION, f"race-{index}")
            return True
        except Denied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert not any(pool.map(execute, range(8)))
    assert state.authenticate(session)["remaining"] == 19


def test_expiry_and_restart_do_not_reset_grant_issuance_cap(
    state: State, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Grant churn has a durable lifetime cap, not only a live-grant cap."""
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1000)
    session = token(state.issue_session("agent", 3600, 1000))
    for batch in range(4):
        timestamp = 1000 + batch
        monkeypatch.setattr("git_broker.state.time.time", lambda now=timestamp: now)
        for _ in range(64):
            state.request_grant(session, read_plan(), REVISION, 1)
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1004)
    restarted = State(state.root)
    with pytest.raises(Denied, match="issuance limit"):
        restarted.request_grant(session, read_plan(), REVISION, 1)
    assert restarted.authenticate(session)["remaining"] == 1000
    with sqlite3.connect(state.path) as connection:
        assert connection.execute("SELECT count(*) FROM grants").fetchone()[0] == 256


def test_cumulative_issuance_limit_is_atomic(
    state: State, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent grant requests cannot exceed the persisted lifetime cap."""
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1000)
    session = token(state.issue_session("agent", 3600, 1000))
    for batch in range(4):
        timestamp = 1000 + batch
        monkeypatch.setattr("git_broker.state.time.time", lambda now=timestamp: now)
        for _ in range(64 if batch < 3 else 63):
            state.request_grant(session, read_plan(), REVISION, 1)
    monkeypatch.setattr("git_broker.state.time.time", lambda: 1004)
    barrier = Barrier(8)

    def issue(_: int) -> bool:
        barrier.wait()
        try:
            state.request_grant(session, read_plan(), REVISION, 1)
            return True
        except Denied:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(issue, range(8))) == 1
    with sqlite3.connect(state.path) as connection:
        assert connection.execute("SELECT count(*) FROM grants").fetchone()[0] == 256
