# Git credential broker

A Python 3.12+ broker for scoped Git operations by AI agents.

**Status: tested security prototype. Not approved for production credentials.**
See [release gates](docs/DEPLOYMENT.md) and [independent review](docs/SECURITY-REVIEW.md).

The broker retains the real SSH key or HTTPS token. Agents receive a revocable session.
Standing policy can grant a short-lived, single-use capability for one exact operation.
Neither MCP nor the agent CLI exposes provider credentials or owner administration.

## Implemented

- GitHub/GitLab-compatible SSH and HTTPS Git transports; no `gh` dependency.
- Repository, branch, operation, principal, expiry, and operation-budget policy.
- Hard deny for configured default/protected branches, even if an allow rule matches.
- Full bundle digest and commit binding; only fast-forward remote branch updates.
- Durable single-use grants, idempotency records, revocation, and audit events.
- Conservative deletion tombstones and verified recovery bundles before enabled deletions.
- AES-GCM local credential vault. Local key storage has explicit limits.
- Unix-socket daemon, CLI client, and agent-side stdio MCP adapter.
- `git broker-push` command for pushing HEAD through the broker.

Ordinary `git push` is not intercepted. Do not give agents another write credential.
A wrapper or Git alias alone is not a security boundary.

## Development

```sh
uv sync --frozen
uv run ruff check src tests
uv run mypy src tests
uv run pytest -q
# Linux verification; network is disabled during tests.
docker build -f Dockerfile.test -t git-broker-tests .
docker run --rm --network none git-broker-tests
```

Follow PEP 8 naming/style, PEP 257 docstrings, PEP 484 typing, PEP 561 package typing,
and PEP 517/518/621 packaging. Ruff and strict mypy enforce the configured subset.
These checks do not prove security or claim compliance with every Python PEP.
An inactive GitHub Actions workflow is in `docs/ci-check.yml.example`. Publishing
credentials lack workflow scope, so no hosted CI run is claimed.

## Owner CLI

Run the owner CLI as a dedicated broker account, not the agent account.
Use a disposable repository and key while the release gates remain open.

```sh
git-broker --root /var/lib/git-broker init
git-broker --root /var/lib/git-broker policy-apply examples/policy.json
git-broker --root /var/lib/git-broker credential-set gitlab-project ssh --file /secure/test-key
git-broker --root /var/lib/git-broker session-issue agent-one --out /secure/session.token
git-broker --root /var/lib/git-broker serve --socket /run/git-broker/broker.sock --socket-gid 1234
```

Create `/run/git-broker` as broker-owned, group-readable/traversable, not group-writable.
Replace `1234` with an authorized client group. The socket defaults to mode 0600;
`--socket-gid` changes it to 0660. The group grants connectivity, not operation permission.
Deliver the session file to its agent using owner-controlled tooling and mode 0600.
The agent must own its session file. Never deliver the provider key or vault directory.

The example denies writes until the owner sets `automation_reviewed` to true.
First check branch-triggered CI, deployments, pipelines, webhooks, and secrets exposure.
This field is an owner attestation, not automatic CI inspection.

## Agent CLI and MCP

```sh
# Run in the agent's worktree. Reads the tip, creates a full HEAD bundle, then requests a push.
git broker-push --socket /run/git-broker/broker.sock --token-file ~/.broker-session \
  --repository project --branch agents/agent-one/task-123

# MCP stdio server to configure in the agent's MCP client.
git-broker-client --socket /run/git-broker/broker.sock --token-file ~/.broker-session --mcp
```

The MCP tool `broker_request` accepts `scope`, `grant`, `execute`, and `operation` actions.
An execution includes `plan`, `grant`, `request_id`, and optional base64 `payload`.
See `OperationPlan` in `src/git_broker/models.py` for the strict schema.
There is no automatic retry of a write after an uncertain result. Query operation state.
The helper spends two operation units: one metadata read and one push.

Read permission currently means branch-tip metadata, not clone/fetch of repository content.
Local merges, squashes, and rebases remain local Git operations under agent privileges.
Only resulting authorized fast-forward remote changes can pass through this broker.
Tags, provider APIs, PR/MR merge, and repository settings are not exposed.

## Architecture

```mermaid
sequenceDiagram
    actor Owner
    participant Agent
    participant Broker
    participant Policy
    participant Vault
    participant GitHost
    Owner->>Broker: Enroll credential, install policy, issue session
    Owner->>Agent: Deliver broker-only session
    Agent->>Broker: Exact plan + session
    Broker->>Policy: Check principal, repo, branch, action, limits
    Policy-->>Broker: Allow or deny
    Broker-->>Agent: Single-use grant bound to plan + policy revision
    Agent->>Broker: Grant + plan + immutable bundle + request ID
    Broker->>Policy: Recheck live policy and session
    Broker->>Broker: Atomically reserve grant and budget; persist intent
    Broker->>Vault: Retrieve upstream credential internally
    Broker->>GitHost: Validate current tip; execute constrained Git update
    GitHost-->>Broker: Result
    Broker->>Broker: Persist sanitized outcome
    Broker-->>Agent: Result or uncertain state; never upstream credential
```

Provider-neutral policy and orchestration are separate from credential custody,
capability storage, Git execution, and transport. Protocols permit replacement adapters.
New adapters must preserve the authorization contract and adversarial tests.
Jev/Strands can suggest policy or explain denials later. They do not authorize writes.

Design reference: [unYOLO](https://github.com/osolmaz/unyolo) and the owner's proposal.
See [SPEC.md](SPEC.md) for source provenance and the broader target design.
The implementation does not claim all target-spec requirements are complete.
