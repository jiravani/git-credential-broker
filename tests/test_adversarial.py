"""Independent adversarial regression tests for authorization boundaries."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from git_broker.errors import Denied, ExecutionError
from git_broker.executor import Credential
from git_broker.files import read_file
from git_broker.models import BrokerConfig, OperationPlan, Principal, Repository, Rule
from git_broker.policy import parse_config
from git_broker.service import Broker
from git_broker.state import State
from git_broker.vault import Vault


@pytest.fixture
def adversarial_policy() -> BrokerConfig:
    """Build overlapping allow rules and an explicit deny for one runtime."""
    return BrokerConfig(
        repositories={
            "repo": Repository(
                backend="ssh",
                remote="ssh://git@example.invalid/team/repo.git",
                automation_reviewed=True,
                default_branch="trunk",
                protected=["main", "master", "release/*"],
            )
        },
        principals={
            "alice": Principal(
                rules=[
                    Rule(
                        repository="repo",
                        operations=["push", "read", "delete"],
                        branches=["feature/*", "main", "trunk", "release/*"],
                    ),
                    Rule(
                        repository="repo",
                        operations=["read"],
                        branches=["feature/*"],
                        deny_branches=["feature/blocked/*"],
                    ),
                ]
            )
        },
    )


def push_plan(branch: str = "feature/alice") -> OperationPlan:
    """Construct a valid exact push request without a provider credential."""
    return OperationPlan(
        operation="push", repository="repo", branch=branch,
        commit="a" * 40, payload_digest="b" * 64,
    )


@pytest.mark.parametrize("branch", ["main", "trunk", "release/v1", "feature/blocked/x"])
@pytest.mark.parametrize("operation", ["push", "delete"])
def test_deny_overrides_allows(
    adversarial_policy: BrokerConfig, branch: str, operation: str
) -> None:
    """Overlapping allows cannot cancel global or explicit ref restrictions."""
    plan = push_plan(branch) if operation == "push" else OperationPlan(
        operation="delete", repository="repo", branch=branch, expected_old="a" * 40
    )
    with pytest.raises(Denied):
        adversarial_policy.authorize("alice", plan)


@pytest.mark.parametrize("branch", [
    "refs/heads/main", "feature2/alice", "feature", "master", "FEATURE/alice",
])
def test_namespace_lookalikes_denied(adversarial_policy: BrokerConfig, branch: str) -> None:
    """Names outside the exact allowed subtree never inherit its authority."""
    with pytest.raises(Denied):
        adversarial_policy.authorize("alice", push_plan(branch))


@pytest.mark.parametrize("branch", [
    "--all", "feature/../main", "feature//main", "feature/x.lock", "feature/.hidden",
    "feature/x:main", "feature/x\nmain", "feature/x\x00", "feature/é", "feature/*",
    "feature/x@{1}", "feature/x~1", "/feature/x", "feature/x/", "feature/x.",
])
def test_revision_and_option_injection_rejected(branch: str) -> None:
    """Git options, revision syntax, Unicode and invalid refs fail parsing."""
    with pytest.raises(ValidationError):
        push_plan(branch)


@pytest.mark.parametrize("field", ["remote", "credential", "force", "args", "username"])
def test_agent_cannot_select_executor_inputs(field: str) -> None:
    """Agent wire plans cannot smuggle destination, auth or Git arguments."""
    values = push_plan().model_dump()
    values[field] = "attacker"
    with pytest.raises(ValidationError):
        OperationPlan.model_validate(values)


def test_unknown_principal_denied(adversarial_policy: BrokerConfig) -> None:
    """A claimed model name cannot substitute for enrollment."""
    with pytest.raises(Denied):
        adversarial_policy.authorize("operator", push_plan())


def test_plan_hash_binds_every_write_field() -> None:
    """Changing a single effect-bearing field changes the canonical digest."""
    original = push_plan()
    for field, value in {
        "repository": "elsewhere", "branch": "feature/bob", "expected_old": "c" * 40,
        "commit": "d" * 40, "payload_digest": "e" * 64,
    }.items():
        changed = OperationPlan.model_validate({**original.model_dump(), field: value})
        assert changed.digest() != original.digest()


@pytest.mark.parametrize("operation", ["force_push", "mirror", "merge", "shell", "tag"])
def test_unsupported_operations_are_closed(operation: str) -> None:
    """Future operation names do not implicitly acquire existing authority."""
    values = push_plan().model_dump()
    values["operation"] = operation
    with pytest.raises(ValidationError):
        OperationPlan.model_validate(values)


@pytest.mark.parametrize("change", ["automation", "disabled", "destination", "protection"])
def test_policy_revision_binds_security_settings(
    adversarial_policy: BrokerConfig, change: str
) -> None:
    """Every privilege-relevant owner edit invalidates old revision bindings."""
    original_revision = adversarial_policy.revision()
    data = adversarial_policy.model_dump()
    if change == "automation":
        data["repositories"]["repo"]["automation_reviewed"] = False
    elif change == "disabled":
        data["principals"]["alice"]["enabled"] = False
    elif change == "destination":
        data["repositories"]["repo"]["remote"] = "ssh://git@other.invalid/team/repo.git"
    else:
        data["repositories"]["repo"]["protected"].append("feature/*")
    changed = BrokerConfig.model_validate(data)
    assert changed.revision() != original_revision
    if change != "destination":
        with pytest.raises(Denied):
            changed.authorize("alice", push_plan())


@pytest.fixture
def adversarial_state(tmp_path: "Path") -> "State":
    """Create isolated persistent authorization state."""
    return State(tmp_path / "broker")


def test_cross_session_grant_theft(adversarial_state: "State") -> None:
    """A second session cannot use a stolen grant, even for the same principal."""
    alice = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    impostor = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    grant = str(adversarial_state.request_grant(alice, push_plan(), "a" * 64, 30)["token"])
    with pytest.raises(Denied):
        adversarial_state.begin(impostor, grant, push_plan(), "a" * 64, "stolen")
    assert adversarial_state.authenticate(alice)["remaining"] == 5


def test_grant_cannot_widen_or_survive_revision(adversarial_state: "State") -> None:
    """Plan substitution and policy replacement do not consume or authorize a grant."""
    token = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    grant = str(adversarial_state.request_grant(token, push_plan(), "a" * 64, 30)["token"])
    with pytest.raises(Denied):
        adversarial_state.begin(token, grant, push_plan("feature/bob"), "a" * 64, "changed")
    with pytest.raises(Denied):
        adversarial_state.begin(token, grant, push_plan(), "b" * 64, "revision")
    assert adversarial_state.authenticate(token)["remaining"] == 5


def test_ambiguous_execution_cannot_replay_after_restart(adversarial_state: "State") -> None:
    """A committed intent stays spent when the broker loses the final outcome."""
    token = str(adversarial_state.issue_session("alice", 60, 1)["token"])
    grant = str(adversarial_state.request_grant(token, push_plan(), "a" * 64, 30)["token"])
    original = adversarial_state.begin(token, grant, push_plan(), "a" * 64, "once")
    restarted = State(adversarial_state.root)
    duplicate = restarted.begin(token, grant, push_plan(), "a" * 64, "once")
    assert original["id"] == duplicate["id"]
    assert original["newly_reserved"] is True
    assert duplicate["newly_reserved"] is False
    with pytest.raises(Denied):
        restarted.begin(token, grant, push_plan(), "a" * 64, "different-id")
    assert restarted.authenticate(token)["remaining"] == 0


def test_delete_tombstone_blocks_recreation(adversarial_state: "State") -> None:
    """Delete-plus-create cannot bypass the no-published-history-rewrite boundary."""
    token = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    deletion = OperationPlan(
        operation="delete", repository="repo", branch="feature/alice", expected_old="a" * 40
    )
    grant = str(adversarial_state.request_grant(token, deletion, "a" * 64, 30)["token"])
    operation = adversarial_state.begin(token, grant, deletion, "a" * 64, "delete")
    adversarial_state.finish(str(operation["id"]), {"deleted": True}, True)
    creation = push_plan()
    new_grant = str(adversarial_state.request_grant(token, creation, "a" * 64, 30)["token"])
    with pytest.raises(Denied):
        adversarial_state.begin(token, new_grant, creation, "a" * 64, "recreate")


def test_cross_session_operation_read_denied(adversarial_state: "State") -> None:
    """Opaque operation IDs do not replace authorization checks."""
    token = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    other = str(adversarial_state.issue_session("bob", 60, 5)["token"])
    grant = str(adversarial_state.request_grant(token, push_plan(), "a" * 64, 30)["token"])
    operation = adversarial_state.begin(token, grant, push_plan(), "a" * 64, "first")
    with pytest.raises(Denied):
        adversarial_state.get_operation(other, str(operation["id"]))


def test_capabilities_never_persist_in_cleartext(adversarial_state: "State") -> None:
    """State and audit store verifiers rather than reusable bearer secrets."""
    token = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    grant = str(adversarial_state.request_grant(token, push_plan(), "a" * 64, 30)["token"])
    adversarial_state.begin(token, grant, push_plan(), "a" * 64, "first")
    for path in adversarial_state.root.iterdir():
        if path.is_file():
            content = path.read_bytes()
            assert token.encode() not in content
            assert grant.encode() not in content


@pytest.mark.parametrize("mode", [0o755, 0o777, 0o750, 0o770])
def test_state_rejects_shared_directory(tmp_path: "Path", mode: int) -> None:
    """Refuse unsafe existing permissions rather than silently repairing them."""
    root = tmp_path / "shared"
    root.mkdir(mode=0o700)
    root.chmod(mode)
    with pytest.raises(Denied):
        State(root)


def test_state_database_symlink_cannot_target_other_file(tmp_path: "Path") -> None:
    """Opening state cannot follow a preexisting link into an unrelated file."""
    root = tmp_path / "broker"
    root.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("do not touch")
    victim.chmod(0o600)
    (root / "state.sqlite3").symlink_to(victim)
    with pytest.raises(Denied):
        State(root)
    assert victim.read_text() == "do not touch"


def test_vault_ciphertext_cannot_move_between_slots(tmp_path: Path) -> None:
    """Authenticated encryption binds credential names, not just ciphertext bytes."""
    vault = Vault(tmp_path / "vault", b"k" * 32)
    vault.put("alice", "https", b"canary-secret-never-return")
    original = vault.root / "alice.https.sealed"
    forged = vault.root / "bob.https.sealed"
    forged.write_bytes(original.read_bytes())
    forged.chmod(0o600)
    repository = Repository(
        backend="https", remote="https://example.invalid/repo.git", credential="bob"
    )
    with pytest.raises(Denied, match="integrity"):
        vault.get(repository)
    assert b"canary-secret-never-return" not in original.read_bytes()


def test_vault_tamper_and_missing_key_fail_closed(tmp_path: Path) -> None:
    """Modified records and missing master keys never trigger credential fallback."""
    vault = Vault.local(tmp_path / "vault", initialize=True)
    vault.put("alice", "https", b"canary")
    record = vault.root / "alice.https.sealed"
    value = bytearray(record.read_bytes())
    value[-1] ^= 1
    record.write_bytes(value)
    with pytest.raises(Denied):
        vault.get(Repository(
            backend="https", remote="https://example.invalid/repo.git", credential="alice"
        ))
    (vault.root / "master.key").unlink()
    with pytest.raises(Denied):
        Vault.local(vault.root)
    assert not (vault.root / "master.key").exists()


@pytest.mark.parametrize("slot", ["../master", "/tmp/key", "x/../../x", "--key", "x\x00"])
def test_vault_rejects_path_injection(tmp_path: Path, slot: str) -> None:
    """Credential slot names cannot escape the vault directory."""
    vault = Vault(tmp_path / "vault", b"k" * 32)
    with pytest.raises(Denied):
        vault.put(slot, "https", b"canary")


def test_sensitive_file_hardlink_is_rejected(tmp_path: Path) -> None:
    """Even a private regular file cannot alias a secret through a second pathname."""
    source = tmp_path / "secret"
    source.write_bytes(b"canary")
    source.chmod(0o600)
    linked = tmp_path / "alias"
    linked.hardlink_to(source)
    with pytest.raises(Denied):
        read_file(linked, 128)


def test_policy_duplicate_fields_fail_closed() -> None:
    """Ambiguous policy documents cannot depend on parser-specific last-key behavior."""
    with pytest.raises(Denied):
        parse_config(b'{"version":1,"version":1,"repositories":{},"principals":{}}')


class ReviewPolicy:
    """Allow the reviewer to simulate an owner policy edit between grant and dispatch."""

    def __init__(self, config: BrokerConfig) -> None:
        self.config = config

    def load(self) -> BrokerConfig:
        """Return the current trusted test configuration."""
        return self.config


class ReviewCredentials:
    """Record whether authorization reached credential retrieval."""

    def __init__(self) -> None:
        self.reads = 0

    def get(self, repository: Repository) -> "Credential | None":
        """Count accesses without exposing a real credential."""
        self.reads += 1
        return None


class ReviewExecutor:
    """Record dispatches and optionally simulate a secret-bearing adapter exception."""

    def __init__(self, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail

    def execute(
        self, repository: Repository, plan: OperationPlan, payload: bytes,
        credential: "Credential | None",
    ) -> dict[str, object]:
        """Return harmless metadata or simulate an uncertain upstream outcome."""
        self.calls += 1
        if self.fail:
            raise RuntimeError("CANARY-UPSTREAM-SECRET")
        return {"commit": "a" * 40}


def test_policy_change_stops_dispatch_before_credentials(
    adversarial_state: State, adversarial_policy: BrokerConfig,
) -> None:
    """Revoked policy cannot use an already-issued grant or touch upstream secrets."""
    source = ReviewPolicy(adversarial_policy)
    credentials = ReviewCredentials()
    executor = ReviewExecutor()
    broker = Broker(adversarial_state, source, credentials, executor, adversarial_state.root)
    session = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    plan = OperationPlan(operation="read", repository="repo", branch="feature/alice")
    grant = str(broker.request_grant(session, plan)["token"])
    data = source.config.model_dump()
    data["principals"]["alice"]["enabled"] = False
    source.config = BrokerConfig.model_validate(data)
    with pytest.raises(Denied):
        broker.execute(session, grant, plan, b"", "after-disable")
    assert credentials.reads == 0
    assert executor.calls == 0


def test_unexpected_executor_errors_are_sanitized_and_not_replayed(
    adversarial_state: State, adversarial_policy: BrokerConfig,
) -> None:
    """An uncertain failing adapter neither leaks its message nor gets retried."""
    executor = ReviewExecutor(fail=True)
    broker = Broker(
        adversarial_state, ReviewPolicy(adversarial_policy), ReviewCredentials(),
        executor, adversarial_state.root,
    )
    session = str(adversarial_state.issue_session("alice", 60, 5)["token"])
    plan = OperationPlan(operation="read", repository="repo", branch="feature/alice")
    grant = str(broker.request_grant(session, plan)["token"])
    with pytest.raises(ExecutionError) as error:
        broker.execute(session, grant, plan, b"", "uncertain")
    assert "CANARY" not in str(error.value)
    repeated = broker.execute(session, grant, plan, b"", "uncertain")
    assert repeated["state"] == "failed_or_unknown"
    assert repeated["result"] is None
    assert executor.calls == 1
