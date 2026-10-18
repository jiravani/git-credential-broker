# Internal contracts — implementation coordination

Python 3.12+, PEP 8/257/484, strict typing, static safe error messages. Shared models are in src/git_broker/models.py. Parent owns models.py, policy/config loader, vault, service, CLI, HTTP/MCP, client, docs/integration. Contributors do not change these without coordination.

## State ownership

Implement state.py with State(root: Path). Uses owner-only SQLite and safe filesystem creation. Structured dataclasses allowed.

Required API (all keywords accepted):
- issue_session(principal: str, ttl: int, uses: int) -> dict[str, object] with id, token, expires. Owner CLI only.
- authenticate(token: str) -> dict[str, object] with id, principal, expires, remaining. Revoked/expired invalid; zero remaining still may read results.
- request_grant(session_token: str, plan: OperationPlan, revision: str, ttl: int) -> dict[str, object] with id, token, expires. Cap expiry by session; no usage is consumed until execute; bound outstanding grant count (e.g. 64). Store token verifiers only, never raw capabilities.
- begin(session_token: str, grant_token: str, plan: OperationPlan, revision: str, request_id: str) -> dict[str, object] with id,state,result. Atomically revalidate tokens, session/grant expiry, revision/digest, use budget, and single-use grant; reserve execution, persist intent BEFORE return. Return prior operation on same session/idempotency key+plan; do not redispatch. Deny key reuse different plan or different grant; cross-session access denied. State states reserved/succeeded/failed_or_unknown. Concurrency must not double spend.
- finish(operation_id: str, result: dict[str, object] | None, succeeded: bool) -> None. Persist result safe supplied by core; append audit event.
- get_operation(session_token: str, operation_id: str) -> dict[str, object] caller-owned only.
- revoke(session_id: str) -> bool.
- audit(limit: int=100) -> list[dict[str, object]] owner-only.
No automatic retry of uncertain executions. No release of budgets after ambiguous failure. Test durable restart, expiry, race, revocation, idempotency, symlinks/file modes, no raw tokens at rest. Public errors from errors.py.

## Git executor ownership

Implement executor.py and credentials helper(s) if required. API:
- Credential(value: bytes, kind: Literal['https','ssh']) dataclass, never repr value.
- Executor protocol: execute(repository: Repository, plan: OperationPlan, payload: bytes, credential: Credential | None) -> dict[str, object].
- GitExecutor(root: Path, allow_local_test: bool=False, max_bundle_bytes: int=8388608).
- `push`: self-contained bundle with exactly HEAD equal plan.commit, SHA256 bound payload, hermetic fresh bare repo, checked object integrity, no hooks/config/env from agent; fetch remote exact branch+verify expected tip; ancestry proof; CAS write. No force/mirror/delete hidden in push. Exact pinned HTTPS/SSH destinations from owner config only. SSH key broker-only temp file, strict known_hosts, shell-safe fixed remote path; no agent forwarding. HTTPS auth helper no secrets in argv or returned output. Never return subprocess stdout/stderr. Sanitize all failures.
- `read`: return branch tip metadata only (commit/branch/repository), NOT clone/export full repo. Can later add blob transport. Do not call writes.
- `delete`: optional explicit policy opt-in, expected-tip CAS, preserve complete recoverable bundle in root/recovery with private permissions and durable fsync before remote delete. Fail closed on recovery failure, preserve metadata for later recovery, return backup handle not raw paths. No protected branch writes (enforced again defensively).
- Production accepts ssh://git@host/path.git or canonical https://host/path.git only; strict ASCII path; reject options, query/fragment/userinfo surprises/port invalid. Arbitrary owner-controlled endpoints supported, not agent URLs. Test backend local_test accepts absolute local bare path ONLY when explicit constructor flag; production rejects it. Fixed protocol commands, clean config/template environment; process-group timeouts, bounded disk/output where practical. Use Linux resource limits in hardened deployment and state unverified parser isolation clearly.
- Local tests use disposable bare Git repos. Add own tests/test_executor.py. Never use real upstream credentials/remote writes.
