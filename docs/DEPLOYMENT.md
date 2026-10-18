# Deployment and production release gates

Status: **production deployment blocked**. This repository is a tested implementation,
not a completed production security boundary.

## Enforced scope

The broker controls supported remote Git effects performed with credentials it owns.
It does not control every shell command or all actions on the VM.
A feature-branch push can still contain malicious code or trigger a deployment.
Branch authorization does not prove that commit contents are safe.

Agents must not have another provider token, an SSH agent with a write key,
a shared credential helper, root, sudo, a Docker socket, or hypervisor control.
Agents must not run as the broker UID. Agent sessions are bearer capabilities;
any process that steals one can use its scope. Model names are not authenticated identities.

Agent-readable local repositories are not branch-scoped read sandboxes.
Normal Git object access can expose reachable history. Current broker read support
returns only the configured branch tip; it does not implement selective clone/fetch.
Local worktrees share metadata. This broker cannot prevent an agent deleting files
or rewriting local refs to which its Linux UID already has write access.

## Required before real production credentials

- Run binary Git parsing as a separate unprivileged worker. Give it no credentials,
  no network, and no writable path into broker state. Current parser subprocesses
  run as the broker UID. Clean environment and Git fsck do not close this gap.
- Verify cross-UID isolation on the target Linux VM. Test denied vault reads,
  ptrace/process access, unauthorized socket access, policy edits, and alternate egress.
- Place aggregate disk, memory, CPU, process, network, and operation-deadline limits.
  Current implementation has bounded requests/native commands and single dispatch,
  but no aggregate disk quota, full wall-clock deadline, or multi-instance scheduler.
- Verify GitLab Enterprise and GitHub with disposable SSH/HTTPS identities and real
  protected-branch behavior. GitHub SSH/HTTPS feature writes and broker denials now have live evidence in
  GITHUB-LIVE-TEST.md. GitLab Enterprise and provider-side protection conformance remain open.
- Keep the configured default/protected branch manifest current. The implementation
  does not discover live provider rules. A remote default-branch rename can create drift.
- Check all branch-triggered automation before enabling writes. Keep
  `automation_reviewed: false` until that review completes. No automatic CI gate exists.
- Establish credential rotation, encrypted backups, recovery drills, storage quota,
  audit retention, and external tamper-evident audit export.
- Obtain a human security review of the deployment and trusted computing base.

## Local vault profile

The vault uses AES-GCM and binds ciphertext to its named credential slot and type.
Files are broker-owned and mode 0600. The local master key is in the same protected
directory. This protects against accidental plaintext exposure and ciphertext tampering.
It does **not** protect against theft of that entire directory, root, or broker compromise.
`Vault(root, key)` permits an external key provider; no KMS integration ships here.

## Operational behavior

- Apply policy through `policy-apply`, which shares the dispatch lock.
- Revoke a session through `session-revoke`. Revocation prevents future admission;
  it cannot recall a write already sent upstream.
- Existing admitted execution can delay policy application until it releases the lock.
- Do not run multiple API workers against the same state; the single-instance
  admission limit is process-local, although capability spending is database-atomic.
- A crash after intent persistence creates an uncertain operation. Do not retry it
  automatically. Reconcile remote state before an owner authorizes a new operation.
- Deletion tombstones are conservative and persistent, even after an uncertain failure.
  No agent endpoint clears them. Keep deletion disabled unless explicitly needed.
- A stale-tip operation that finds the desired tip already present can be treated by
  Git as a no-op success. It cannot change that ref to a different value.
- Credential, state, and policy parent directories must remain owner-controlled.
  Final-path symlink checks do not defend against a hostile owner of parent directories.
- Stop the daemon before removing a stale Unix socket. Startup refuses an existing path.
- The owner manages session-file delivery. There is no built-in agent enrollment UI.

## Extensibility

`PolicySource`, `CredentialProvider`, and `Executor` define typed replacement boundaries.
Adapters are trusted code. Do not load agent-selected plugins into the broker process.
Add a new operation only after defining its exact effect, immutable authorization plan,
idempotency behavior, audit fields, denial cases, and provider conformance tests.

Jev or Strands Decider can classify proposed operations in shadow mode or help explain
policy. Neither can override deterministic denial or mint credentials. No inference
integration is enabled in this implementation.
