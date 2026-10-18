# Adversarial verification evidence

This is reproducible evidence of specific controls. It is not proof that every
bad or questionable agent action is impossible. Content safety and host isolation
are separate from Git authorization.

## Live-provider follow-up

GitHub SSH and HTTPS checks now pass against disposable branches. See
[GITHUB-LIVE-TEST.md](GITHUB-LIVE-TEST.md). This does not close Linux isolation
or GitLab Enterprise gates. The original offline evidence below remains unchanged.

## Desktop Linux follow-up

25 cross-UID isolation checks and all 143 regression tests passed in a
network-disabled Desktop container. See [LINUX-DESKTOP-ISOLATION.md](LINUX-DESKTOP-ISOLATION.md).
This is fixture-specific evidence, not parser sandboxing or production deployment approval.

## Observed results

- macOS ARM64: **143 tests passed**, zero failures, zero skips.
- Ruff: all checks passed across source and tests.
- Strict mypy: passed across 18 source/test files.
- Dependency audit: no known vulnerabilities reported for installed dependencies.
  The local unpublished project itself is not in the advisory database and was skipped.
- Independent reviewer: 88 tests across adversarial and transport suites passed.
- Linux ARM64, non-root and network-disabled: **143 passed**, zero failures, zero skips.
- Machine-readable evidence: `test-results.xml` and `linux-test-results.xml`.
- `source-sha256.json` binds this evidence to the reviewed implementation/test files.

## Attack-to-evidence mapping

| Attempt | Expected evidence | Test |
| --- | --- | --- |
| Push `main`, `master`, or `release/*` despite an overlapping allow | Denied; remote refs remain empty | `test_executor.py::test_protected_branches` |
| Push `main` through the complete CLI/HTTP/Git path | Client fails; remote has no `main`; allowed feature push succeeds | `test_integration.py::test_cli_socket_push_and_mcp` |
| Replace published history with unrelated history | Denied; original remote tip stays unchanged | `test_executor.py::test_non_fast_forward_and_stale_tip_denied` |
| Race another writer after the broker checks the tip | Exact lease rejects conflicting mutation | `test_executor.py::test_remote_race_rejected_by_lease` |
| Delete, then recreate a branch to bypass no-rewrite policy | Durable tombstone denies recreation, including restart | `test_state.py::test_delete_tombstone_survives_failed_execution_and_restart` |
| Delete when backup cannot be secured | Denied; original remote tip remains | `test_executor.py::test_failed_backup_prevents_deletion` |
| Spend one grant concurrently | Exactly one reservation succeeds | `test_state.py::test_atomic_single_use_grant_under_race` |
| Race grants against remaining operation budget | Atomic budget permits only allowed count | `test_state.py::test_atomic_budget_across_independent_grants` |
| Replay an operation after crash/restart | Existing reservation never redispatches | `test_adversarial.py::test_ambiguous_execution_cannot_replay_after_restart` |
| Change plan, repository, branch, commit, or policy after grant | Digest/revision mismatch denied | `test_adversarial.py::test_grant_cannot_widen_or_survive_revision` |
| Steal a different session's grant or operation ID | Caller binding denies use/read | `test_adversarial.py::test_cross_session_grant_theft` and `test_cross_session_operation_read_denied` |
| Forge, expire, revoke, or exhaust capabilities | Denied without regaining budget | `test_state.py::test_expiry_budget_revocation_and_policy` |
| Submit option injection, odd refs, or agent-chosen credential/URL | Strict schema or destination validation rejects input | `test_adversarial.py::test_revision_and_option_injection_rejected` and `test_agent_cannot_select_executor_inputs` |
| Upload corrupt, changed, extra-head, or incomplete bundles | Integrity/digest/exact HEAD checks fail | `test_executor.py::test_payload_tamper_size_and_extra_heads`, `test_corrupt_pack_denied`, `test_prerequisite_bundle_rejected` |
| Invoke owner actions over authenticated agent API | No admin route; request rejected | `test_transport.py::test_owner_actions_unreachable_from_agent_api` |
| Leak persisted bearer tokens or exchange encrypted vault slots | No cleartext capability; AEAD decryption fails for moved/tampered ciphertext | `test_adversarial.py::test_capabilities_never_persist_in_cleartext`, `test_vault_ciphertext_cannot_move_between_slots` |
| Cancel a request to admit more concurrent workers | Admission stays closed until worker finishes | `test_transport.py::test_cancelled_request_does_not_reopen_worker_admission` |
| Repeatedly expire/reissue grants to grow storage without limit | Lifetime issuance cap survives restart and races | `test_state.py::test_expiry_and_restart_do_not_reset_grant_issuance_cap` |

Tests use temporary bare repositories, temporary private state, and fake credentials.
They do not mutate the operator's GitHub/GitLab repositories as attack targets.
The native executor tests check actual Git state, not only returned error strings.
The integration test starts real daemon and MCP subprocesses.

## Repeat the evidence

```sh
uv sync --frozen
uv run ruff check src tests
uv run mypy src tests
uv run pytest -q --junitxml=docs/test-results.xml
uv run pip-audit --progress-spinner off
docker build -f Dockerfile.test -t git-broker-tests .
docker run --rm --network none git-broker-tests
```

The first offline Docker attempt failed before test execution because `uv run`
tried to rebuild the editable package and fetch its build backend. The image command
now invokes the installed pytest executable directly. Runtime tests need no network.

GitHub rejected creation of an active Actions workflow because the publishing
credential lacks `workflow` scope. The workflow is supplied as
`ci-check.yml.example`; hosted CI has not run. Local and Linux results above are observed.

## What the evidence does not establish

- Whether an allowed commit contains malicious code, secrets, or a dangerous CI change.
- Whether a feature-branch push triggers production automation.
- Protection from agents with other credentials, root, or the broker UID.
- Protection of agent-writable local files, local refs, or production shell commands.
- Native Git memory-safety isolation from broker credentials.
- Live GitLab Enterprise/GitHub branch-protection conformance or default-branch drift.
- Resistance to every resource exhaustion attack or a compromised host.

These are explicit [production release gates](DEPLOYMENT.md), not implicit guarantees.
