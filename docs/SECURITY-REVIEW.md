# Independent agent adversarial review

Status: Initial source, transport, and adversarial test review complete.
Not an external audit or security certification.

## Scope

Review the Python broker against `SPEC.md`, its implementation contract, and the
operator's requirements. Treat the agent as malicious. No real credentials,
remote writes, or production infrastructure are used in these tests.

The review is performed by a separate agent from the implementation authors.
That provides a second source review, not independent human certification.

## Findings and decisions

### Published-history protection and deletion

Deleting a feature branch and recreating it at an unrelated commit can replace
published history without a force push. Delete permission therefore weakens a
blanket claim that published history cannot be rewritten.

Remediation implemented: `State.begin` persists a repository/branch tombstone
before admitting deletion and rejects subsequent creation under that name.
The independent delete/recreate regression passes. Recovery bundles help
recovery; they do not preserve the old remote ref. Deletion remains an explicit
policy opt-in.

### Static default-branch manifest

A configured protected/default branch is not proof of the provider's current
default branch. A provider-side default-branch change can invalidate an old
manifest. Verify upstream default-branch drift or require operational controls
that keep the manifest current. Do not claim live provider-rule discovery from
a static manifest.

### Trusted parser boundary

Git bundle and pack parsing processes consume attacker-controlled binary input.
Input-size limits alone do not bound decompressed storage, CPU, or parser memory.
The implementation adds native process limits, but parsing still runs under the
broker UID and can access its credential files.
Before a production release, verify resource limits and a separate unprivileged,
networkless parser worker without provider secrets. A passing local Git test
suite does not establish that OS boundary.

### Configuration mutability

Pydantic frozen models prevent field reassignment but do not make contained
lists or dictionaries immutable. Current policy values should stay private to
trusted code. Do not expose mutable configuration objects to untrusted plugins.
Consider immutable containers before adding in-process extension hooks.

## Adversarial regression coverage

`tests/test_adversarial.py` covers:

- Explicit deny overrides overlapping allow rules.
- Default/protected branch push and deletion denial.
- Branch namespace lookalikes and ref-prefix confusion.
- Option injection, revision expressions, invalid names, and control characters.
- Unregistered principal rejection.
- Agent-controlled destination, credential, and argument fields rejected.
- Unsupported operations fail closed.
- Plan hashes bind all effect-bearing fields.
- Policy revision hashes change with security-relevant owner edits.
- Disabled principals and unreviewed automation remain denied.

Independent regression result: **88 passed** across `tests/test_adversarial.py`
(66) and `tests/test_transport.py` (22). Ruff and strict mypy checks pass for both.

Additional verified tests:

- A stolen grant cannot be used by another session, including the same principal.
- Operations cannot be read by another session.
- Changed plans or policy revisions cannot spend a previously issued grant.
- Restart after durable reservation does not dispatch again or restore budget.
- Deletion tombstones block recreation at an unrelated commit.
- Session and grant tokens do not appear as plaintext in persisted state.
- Shared-mode state directories and database symlinks are rejected.
- Vault ciphertext copied to another slot fails authenticated decryption.
- Tampered ciphertext fails closed; missing keys are not regenerated on open.
- Credential slot traversal and sensitive-file hardlinks are rejected.
- Duplicate JSON policy fields are rejected.
- Disabling a principal after grant issuance prevents credential lookup and dispatch.
- Unexpected adapter errors are sanitized. An uncertain outcome is not retried.

These tests use isolated local files and fake adapters. Executor-specific tests
written by the executor author are separate from this independent test count.
Transport verification includes:

- Missing, malformed, revoked, or duplicate bearer authentication is denied.
- Browser Origin headers, duplicate JSON fields, oversized bodies, unknown fields,
  and malformed requests are denied without echoing secrets.
- Owner actions cannot be invoked through the authenticated agent API.
- Transport grant execution preserves single-use and idempotency rules.
- A slow body reader prevents admission of a second request.
- Cancelling a request does not reopen admission while its worker is running.
- A real UDS broker subprocess creates a `0600` socket.
- A real stdio MCP subprocess initializes, lists its tool, and successfully calls
  `scope` through the UDS broker. No bearer token appears in the tool result.

The runtime socket and MCP smoke test uses a disposable local configuration and
performs no upstream Git operation. It does not prove cross-UID deployment
isolation or Linux peer-credential binding.

### Unix socket permission override — fixed

Uvicorn's built-in UDS startup path changes a new socket to `0666`, overriding
the process umask. The original startup path therefore did not establish the
intended socket permissions. The implementation now binds the socket explicitly
in a trusted parent, sets `0600` or an owner-selected group's `0660`, and passes
the bound listener to Uvicorn. The independent subprocess test verifies `0600`.
Socket permissions supplement bearer authentication; this is not peer-UID binding.

### Cancelled request admission — fixed

Cancelling an await of `asyncio.to_thread` does not stop the underlying thread.
The original handler reset its admission flag in `finally`, while work could
continue. The handler now shields the worker and releases admission only after
worker completion. An independent cancellation regression verifies the fix.

### Grant churn — fixed with residual operational limit

Limiting only live grants allowed repeated expiry/reissue without spending an
operation budget. Persisted grants and audit rows could grow for the session's
entire lifetime. The state implementation now enforces a transactional cumulative
limit of 256 grants per session. State-author regression tests cover expiry churn,
restart, and concurrent issuance. Global retention and disk quotas remain operator
responsibilities; pruning must preserve cumulative grant accounting.

### Resource and revocation latency

The global dispatch lock spans the entire Git operation. A slow operation can
delay owner policy application. Each native subprocess has a timeout, but the
pipeline needs an aggregate deadline and admission limits. Session revocation
should not wait on this long lock; queued requests must authenticate again after
acquiring it. Bound disk use across all operations, not just individual files.

## Release assessment

Do not label the current implementation production verified based on this review.
Linux same-VM identity separation, resource isolation, provider conformance,
credential rotation, backup freshness, and a human security audit need separate
evidence. Existing broad upstream credentials reachable by agents defeat
broker-only enforcement even if all broker tests pass.
