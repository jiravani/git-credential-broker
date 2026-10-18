# Agent Git Access Broker — Security and Production Specification

Version: 0.3, Linux shared-VM and standing-policy draft
Date: 2026-10-17
Owner: Project operator
Status: Requirements draft. Not approved for production deployment.

## 1. Purpose and status

Build a credential broker and executor for AI agents that use GitHub and GitLab. Agents receive limited broker capabilities, not upstream credentials. The broker must authorize each remote write and perform it on the agent's behalf.

This specification draws on unYOLO's separation of generic authorization from provider execution. It does not adopt unYOLO wholesale or certify its security. The choice to extend, fork, depend on, or independently implement its components is unresolved.

MUST indicates a release requirement. SHOULD indicates a recommended control with a documented exception process. PROPOSED indicates an unapproved design choice. OPEN indicates a required decision. An unanswered question does not authorize the proposed answer.

An earlier local Python prototype is a proof of concept only. It is GitHub-specific, uses local secret files, and lacks several controls below. It is not included in this specification repository. Its passing tests are not evidence that this specification has been implemented.

## 2. Confirmed requirements

- Support both GitHub and GitLab.
- Do not require the GitHub CLI or GitLab CLI.
- Let an owner enroll upstream credentials through a private control plane.
- Provide MCP access to broker operations.
- Issue separately revocable capabilities to individual agent/model sessions.
- Scope capabilities by repository, operation, and branch/ref.
- Keep full upstream credentials out of agent runtimes and model context.
- Mediate pushes, merges, and other supported remote writes.
- Produce a production-grade security tool, with explicit verification before release.
- Initial audience: the operator's own agents, not unrelated customers.
- Initial hosting: agents and broker share a local VM, primarily Linux. Separate OS identities and agent privilege restrictions are mandatory; their availability remains to be verified.
- Owner administration uses a CLI, not a CI system.
- Evaluate Jev and Strands Decider as optional decision-model components.
- Configure standing policy once; do not require username/password entry or human approval for each allowed low-risk push.
- Agents may request limited read/write grants, including expiring and single-use grants.
- Prefer protected local credential storage for the first deployment, subject to acceptance of its threat limits.
- Agents can use local MCP; normal Git-command behavior must be accommodated in the integration design.
- Default objective: autonomous work on feature branches, without published-history rewrites, protected/default-branch writes, or repository administration.
- Desired scope includes local merges/squashes, likely local rebases and tags, and deletion of eligible nonprotected feature branches.
- CI and review controls are not established yet. Do not assume they provide protection.
- GitLab Enterprise/self-managed is likely; GitHub support remains required. Exact GitLab edition/version and instance are unresolved.
- Use the operator-supplied GitHub repository for specifications and disposable testing, not as authorization to alter production repositories.

A model name is not an authenticated identity. A token assigned to a model session identifies its runtime principal. A copied bearer token can be used by another runtime unless it is sender-bound.

## 3. Non-goals and boundaries

- No arbitrary shell, arbitrary Git argument array, general HTTP proxy, or unrestricted provider API.
- No promise to control local commits, resets, or merges in an agent-owned workspace. Local execution control requires a separate sandbox.
- No claim to prevent malicious but authorized source changes, CI abuse, or sensitive data committed to an allowed branch unless separate content policy is enabled.
- No protection against compromise of the trusted broker host, operator identity, or external key service beyond the chosen threat model.
- No assumption that GitHub or GitLab tokens can encode the broker's branch policy.
- No branch-only confidentiality claim. Git history, reachable objects, and provider read permissions can expose data from other branches. Ref write scope is not a read-security boundary.
- No PR/MR workflow dependency for ordinary Git pushes. Hosted pull/merge requests are separate provider operations.

## 4. Threat model

### 4.1 Untrusted inputs and actors

Treat agent processes, prompts, repositories, Git configuration, hooks, attributes, packfiles, bundles, filenames, submodules, LFS pointers, MCP arguments, and upstream response text as untrusted.

Assume an agent can run arbitrary code within its own runtime. It can modify its Git config, inspect its environment, steal its own token, forge client labels, and deliberately call unauthorized operations. Prompt injection is one way this can happen; authorization MUST not depend on model cooperation.

Assume concurrent legitimate writers, stale approvals, network failures, process crashes, replay attempts, and resource-exhaustion inputs.

### 4.2 Trusted computing base

Explicitly inventory the broker host OS, broker service accounts, authorization engine, provider adapters, credential service, operator authentication, policy distribution, Git/object parsers, audit persistence, and build/update chain.

Agents MUST NOT administer these components or access their runtime sockets, volumes, process memory, or credentials. Running the broker under the agent's account, or under a container runtime the agent controls, does not meet this boundary.

### 4.3 Required invariants

- S1: No upstream secret or usable upstream signed URL reaches an agent-facing response, log, tool argument, environment, or filesystem.
- S2: Every write is classified and authorized before execution. Unknown operations fail closed.
- S3: Effective permission is the intersection of global policy, provider/repository policy, principal capability, and any required approval.
- S4: Deny rules override grants and approvals. No MCP call can widen its own permissions.
- S5: Authorization binds provider instance, repository identity, operation, exact affected refs, object IDs, and relevant arguments.
- S6: Concurrent state changes cannot redirect an authorized write or silently widen its effect.
- S7: Durable audit intent and atomic usage reservation precede remote side effects.
- S8: Agent, operator, approver, and credential-enrollment authority are separate.
- S9: Loss of policy, authorization state, trustworthy time, or credential access never causes fallback to an unrestricted path.
- S10: Revocation blocks all operations not yet admitted for dispatch. Already-dispatched writes may finish and must be reported accurately.

## 5. Architecture

Logical components:

1. Agent interface: MCP and, if selected, native Git transport.
2. Authenticator: maps a capability and optional runtime identity to a principal.
3. Classifier/planner: produces a typed, canonical, immutable operation plan.
4. Policy engine: evaluates the plan against current policy and approvals.
5. Operation store: holds plans, revisions, grants, idempotency records, budgets, and state transitions.
6. Executor: runs bounded Git operations or a registered provider API operation.
7. Credential provider: obtains upstream credentials only for an authorized target and operation.
8. Audit service: durably records intent, dispatch, and outcome without sensitive request content.
9. Operator control plane: enrolls providers, manages policies, issues/revokes capabilities, and handles approvals.

PROPOSED: one management experience and policy schema, with separate GitHub and GitLab worker identities and credential domains. Shared UI does not require one process with every credential.

PROPOSED: reuse reviewed unYOLO authorization, grant lifecycle, protocol, and Git parsing components. Keep new GitLab code in a provider adapter. Maintain a pinned dependency or fork with an upstream-update review process.

Initial platform: Linux, with broker and agents in the same local VM. Implementation ownership model and language remain OPEN. Support for other platforms is deferred.

## 6. Agent interfaces and transport

MCP MUST expose typed operations and structured errors. Token delivery MUST use protected runtime configuration, not model-visible tool parameters. Tool discovery MAY hide unauthorized operations, but execution MUST independently reauthorize every call.

Minimum logical MCP surface:

- `capabilities.inspect`: return the caller's effective permissions, expiry, and remaining budget.
- `grant.request`: request a narrower, expiring capability or exact single-use plan grant. The broker decides whether standing policy permits it without operator interaction.
- `operation.submit`: accept a registered operation and a client idempotency key.
- `operation.get`, `operation.wait`, `operation.list`: expose only caller-authorized operations.
- `operation.cancel`: cancel only before irreversible dispatch; return too-late state otherwise.

MCP is not the owner enrollment or unrestricted token-minting API. A typed `grant.request` operation may request an attenuated grant under an existing authenticated session and standing policy.

### 6.1 Native Git option — decision required

If ordinary `git push` compatibility is required, use a smart-HTTP broker or reviewed remote-helper design. A local helper may supply a broker token, never an upstream token. Parse and authorize the complete multi-ref transaction before forwarding it. Refuse unsupported capabilities rather than passing them through.

Remote URL rewrites are usability features, not security enforcement. Agent runtimes MUST lack direct upstream write credentials. Where required by the threat model, egress restrictions MUST prevent alternative authenticated paths.

If MCP-only operation is selected, define a bounded, authenticated binary upload channel. Do not make large base64 bundles part of model context. Upload handles MUST bind principal, repository, digest, size, expiry, and single-operation use. Validate content before the credential-bearing phase.

PROPOSED: a native Git adapter plus local MCP, both backed by the same authorization engine. Agent-side helpers may request grants automatically under standing policy. The local MCP bridge holds only a broker-session credential. The broker remains in a distinct protected service account within the shared Linux VM.

SSH upstream transport is a first-class candidate because the operator expects to use SSH keys. Any SSH implementation MUST verify pinned or managed host keys and MUST NOT forward an upstream SSH agent socket. Git-over-HTTPS remains an adapter option. Initial transport priority needs confirmation.

OPEN: whether transparent native Git is mandatory at first release, and which agent runtimes require it; required LFS/submodule behavior; SHA-1 and SHA-256 repository requirements.

### 6.2 What SSH does and does not abstract

SSH authenticates transport. It does not encode a broker grant's branch, use count, or expiry. Never give an agent a temporary copy of the real SSH private key or access to the broker's upstream SSH agent. The agent capability is valid only at the broker.

A generic Git push backend can talk to either hosting provider over SSH without a `gh` or `glab` dependency. It MUST use a registered host, pinned host-key policy, repository path, and fixed protocol command. The caller cannot supply a shell command or choose another destination.

Provider identity and APIs still matter for protected/default-branch discovery, repository identity, rename handling, permissions, PR/MR operations, and administrative controls. If API access is unavailable, use an operator-managed, revisioned repository/branch manifest. Bind exact canonical host/path and trusted host identity; fail closed on unknown mappings or drift. Do not silently claim immutable provider-ID or live branch-rule guarantees in that mode. Proving a safe manifest-only drift policy is a release requirement.

The chosen design MUST explain how SSH protocol traffic is mediated. A credential helper alone is insufficient. Options include a broker remote helper, a smart-HTTP front end with an SSH upstream executor, or typed MCP execution. Choose and test one before implementation scope is fixed.

## 7. Identity, capabilities, and revocation

PROPOSED capability fields:

- Random capability ID and authenticated principal ID.
- Issuer, broker audience, tenant, and optional sender-binding identity.
- Allowed provider-instance/repository IDs.
- Allowed operations and typed constraints.
- Ref patterns, expiry, use budget, and concurrency budget.
- Policy revision and revocation epoch.
- Optional parent capability ID if controlled delegation is approved.

Default proposal: opaque tokens with at least 256 bits of cryptographic randomness; store only verifiers. A centralized state check enables revocation and budgets. Do not embed provider secrets in tokens. Do not use long-lived stateless JWTs as the sole authorization state.

PROPOSED defaults: one-hour lifetime, 20 write attempts, no delegation, no force push, no deletion, no administrative operations. These are configurable policy defaults, not approved user requirements.

The broker MAY automatically issue narrower child operation grants to an authenticated agent under an operator-authored standing policy. This is policy evaluation, not permission for an agent to mint arbitrary authority. Requested scope MUST be intersected with the parent session and current policy. An agent cannot choose its authenticated principal, extend expiry, or reset its usage budget.

Single-use execution grants MUST bind one canonical plan and payload digest. They MUST be atomically reserved before dispatch. Repeating the same idempotency key returns the existing result or unknown state; it does not create a second write. A new retry requires fresh authorization. A short time-window grant is not a single-use grant and MUST be labeled separately.

Every operation MUST recheck current policy and revocation at dispatch, including after approval waits and queue waits. Token and grant expiry MUST survive restart without extension. Distributed deployments MUST use authoritative transactional state and bounded time skew. A worker losing authorization connectivity MUST stop admitting writes.

Define a measurable revocation bound before release. PROPOSED: at most five seconds across healthy workers; zero new admissions after a local revocation commit. In-flight writes cannot be recalled.

OPEN: bearer tokens versus mTLS/sender-bound credentials; issuer identity; session lifecycle; allowed delegation.

## 8. Policy and operation semantics

Policy MUST use strict schemas. Reject unknown fields, operations, attributes, ambiguous canonical forms, and invalid ref patterns. Authenticate before repository discovery. Bind repositories to provider-assigned immutable IDs and configured instance identities, not only mutable display paths. Revalidate moves, renames, ownership changes, and installation changes.

Register separate operations:

- `git.fetch`
- `git.branch.create`
- `git.push.fast_forward`
- `git.push.force`
- `git.ref.delete`
- `git.tag.create`, `git.tag.update`, `git.tag.delete`
- `review.create`, `review.update`, `review.comment`
- `review.merge`
- Optional separately gated repository administration operations

Repository writes through REST or GraphQL MUST receive equivalent classification. Blocking Git pushes while allowing unrestricted contents/ref APIs is a bypass.

### 8.1 Push rules

- Validate every ref, old object ID, new object ID, and object format.
- Check all refs in a push. One allowed ref does not authorize another.
- Prove fast-forward ancestry from verified objects. A client assertion is insufficient.
- Reject ambiguous ancestry unless an explicit force-update capability applies.
- Bind the expected previous tip and enforce it atomically upstream.
- Treat creation, deletion, force updates, and tag updates as different operations.
- Refuse mirror pushes and server-specific push options unless explicitly implemented and reviewed.
- Require atomic multi-ref update support or reject multi-ref requests. Do not claim atomicity if the provider can partially apply them.
- Bound compressed bytes, inflated bytes, object sizes, object counts, graph traversal, and total runtime.

### 8.2 Merge rules

A hosted merge approval MUST bind repository IDs, review ID, source and target refs, expected source commit, merge method, policy revision, expiry, and any required target-tip condition.

A broker-created Git merge MUST run in an isolated repository with pinned commits. The final write MUST compare-and-swap the exact target ref.

Provider API merges MUST have a documented atomicity model. Do not assume a prior GET of the target branch makes a later merge API call safe. If the API cannot atomically bind required properties, use a reviewed alternative, narrow the policy contract, or disable that operation. A retargeted PR/MR MUST NOT redirect authority.

PROPOSED: no admin bypass of reviews, checks, merge queues, signing requirements, or protected branches. Provider rules are an additional layer, not a substitute for broker policy. Upstream rejection MUST not trigger a more privileged retry.

Desired local transformations: merge and squash, with rebase likely. Published-history rewriting remains denied. Hosted merge methods, fork reviews, future CI/check requirements, and queue behavior remain OPEN; no privileged bypass is part of the initial profile.

### 8.3 Standing-policy workflow: no per-push login

1. Owner enrolls a provider credential and registers repositories/protected refs once.
2. Owner applies a validated policy and enrolls an agent runtime.
3. Agent authenticates with a bounded broker session, not the owner's credentials.
4. Agent or native Git helper requests an operation and, optionally, a narrow grant.
5. Broker classifies actual effects, computes the current policy intersection, and returns allow, deny, or approval-required.
6. Low-risk matches receive an expiring or single-use grant automatically. No human password prompt occurs.
7. Broker reserves use, verifies exact objects/refs and policy again, and performs the authorized operation with its private upstream credential.
8. Agent receives a sanitized result. The audit records the grant and operation outcome.

No match means deny, not prompt-until-approved. Protected operations stay denied unless the owner explicitly changes policy. Agent-written risk labels never determine authorization.

### 8.4 Proposed conservative policy profile

Risk is assessed from effects and destination, not a command's friendly name.

| Action | Proposed default | Required constraints |
| --- | --- | --- |
| Fetch/read | Automatic, bounded session | Explicit repository allowlist; no write authority; repository-level confidentiality |
| Create feature branch | Automatic single-use grant | Agent-owned namespace; pinned base; not a protected/default/release ref |
| Push feature branch | Automatic single-use grant | Fast-forward proof; all refs in scope; expected-tip check; payload/resource limits |
| Merge locally | Local sandbox operation | Disposable clone/worktree; no production checkout; not a remote authorization |
| Squash/rebase unpublished commits | Local sandbox operation | Discardable agent-owned branch; preserve recovery point; no published ref rewritten |
| Rebase/squash published commits and force push | Deny | New branch or fresh fast-forward-compatible publication instead |
| Push to main/default/protected/release branch | Deny | No agent bypass or automatic promotion in this phase |
| Remote merge into protected branch | Deny | Local merge approval does not authorize a protected remote update |
| Delete own feature branch | Conditional single-use grant | Explicit enablement; verified ownership; exact current tip; nonprotected; retained recoverable ref/object closure |
| Delete another agent's or unknown branch | Deny | Ownership cannot be inferred from client-supplied labels |
| Create a tag | Disabled until namespace/trigger review | Exact new annotated/lightweight-tag policy, permitted target commit, non-release namespace, no deploy side effect |
| Update/delete a tag | Deny | Existing tags may be published/release identities |
| Repository settings, members, keys, hooks, visibility | Deny | Not reachable through generic API tools |
| Force/mirror push; hidden refs; unknown push options | Deny | No raw forwarding fallback |

Deletion recovery requires a broker-managed retained object closure or reliable server-side recovery guarantee. A label saying “backup exists” is not evidence. Define retention and storage limits before enabling deletion. If the recovery precondition fails, deny deletion. Multi-step recovery-plus-delete operations require crash-safe state and reconciliation.

A feature branch is not automatically harmless. Its push can trigger CI or deployments. Before automatic writes, inspect repository automation and enforce that the writable namespace cannot reach privileged workflows, environments, credentials, or runners. Until verified, the repository is not eligible for the automatic production profile. CI is currently absent; revalidate eligibility whenever CI, webhooks, or deployment triggers are introduced. Without provider visibility or controlled configuration, this cannot be guaranteed by Git protocol inspection alone.

Squash does not inherently mean safe. Creating a new squashed commit on an unpublished branch is different from replacing commits already published remotely. Rebase rewrites commit identities even when no files change. Authorization follows the resulting ref transition.

### 8.5 Local worktrees and production safety

Worktrees of one repository share its common Git directory, refs, configuration, and objects. A worktree name or branch checkout does not isolate an untrusted agent. Agents with write access to the common directory can bypass a wrapper and modify local refs directly.

Use separate disposable clones under an agent sandbox for mutually untrusted agents or protected workspaces. A managed local executor is optional for work that must preserve trusted local branches; in that mode agents cannot directly write its repository metadata. Do not claim a remote credential broker enforces local history restrictions in an agent-owned checkout.

The initial product protects remote Git writes. Protecting production databases, cloud APIs, hosts, and files requires separate least-privilege credentials, network isolation, and execution controls. Do not give an agent production SSH access merely because its Git pushes are constrained. Removing the agent's existing broad provider credentials is part of deployment, after a reviewed migration—not part of this specification edit.

## 9. Provider adapters

### GitHub

For API-backed operations, SHOULD use a dedicated GitHub App with only required installation/repository permissions. For Git-only operations, a dedicated broker-owned SSH identity is an option, with separately verified provider-side write access and broker-side ref enforcement. Short-lived installation tokens remain inside the broker. Scope each request to the selected repository where supported. Rotation and installation suspension MUST invalidate affected cached authority.

PAT and SSH credential support MUST each be a separate explicit profile. Existing broad human-account credentials MUST NOT become the production default by convenience.

### GitLab

Support for GitLab.com and self-managed GitLab MUST be decided explicitly. Register each instance's exact HTTPS origin, trusted CA policy, repository IDs, and supported server versions.

Evaluate project/group access tokens, OAuth, or another supported credential mechanism against the selected GitLab edition and version. Do not assume GitHub App token semantics exist on GitLab. Separate repository push access from merge-request API permissions where feasible.

The adapter MUST cover nested namespaces, moved projects, protected branches, protected tags, merge-request SHA guards, revocation, expiration, and provider rate limits. Verify each behavior against current GitLab documentation and live disposable test projects before claiming parity.

Deploy keys may support Git transport but do not automatically provide review API operations. They are not a complete replacement for a provider credential design.

## 10. Credential storage and use

Enroll credentials through an authenticated operator interface with masked entry or sealed upload. Do not enroll secrets through agent MCP, chat, process arguments, shell history, or normal application logs.

Selected initial direction: protected local storage inside the broker VM. Implement encrypted credential records with tightly scoped service-account access. Where practical, wrap the encryption key with an OS key service or virtual TPM; support an owner-unlocked boot profile if unattended restart is not required. The exact unlock mechanism is OPEN.

Do not prompt for a username/password per push. Enrollment/unlock occurs at owner setup or service startup according to the selected profile. Short-lived broker grants cover agent operations thereafter.

External secret manager/KMS or hardware-backed key services remain future options, not prerequisites silently imposed on the first deployment. Use per-provider keys where feasible. Document that plaintext keys available to the broker, full VM snapshots with unlock material, or compromise of its service account can defeat local at-rest encryption.

A local-file profile MAY be supported only as an explicitly accepted threat profile. Encryption with a key beside the ciphertext MUST NOT be described as protection against theft of the full state directory. Full-disk encryption, backup controls, and service-account isolation remain required for that profile.

- Do not place secrets in container images, repositories, model prompts, command lines, or agent-readable environment variables.
- Minimize credential-bearing subprocesses. Prefer protected file descriptors or reviewed helper channels over environment variables.
- Disable core dumps and debug endpoints that expose memory or configuration.
- Never inherit arbitrary proxy, credential-helper, SSH, or Git settings.
- Do not follow redirects with credentials to a different origin. Revalidate any approved redirect and path scope.
- Restrict provider egress to registered instances. Handle DNS changes, internal addresses, and self-hosted instances under an explicit SSRF policy.
- Keep LFS signed URLs and headers inside the broker. Rewrite supported actions to bounded broker capabilities.
- Validate webhook signatures and replay/delivery IDs before changing credential authority.
- Define rotation, revocation, recovery, incident response, and backup-key custody procedures.
- Sanitize outputs as defense in depth. Secret scrubbing is not permission to send credentials to untrusted destinations.

## 11. Operator approval and policy management

Operator authentication MUST be separate from agent authentication. Approvals MUST be bound to a canonical operation or a precisely bounded reusable grant. Show the repository, refs, commits, operation, and risk without trusting agent-written explanatory text.

Initial owner interface: a CLI running as a separate operator identity. Agents cannot invoke its privileged effects through their session credentials or edit its code, policy files, or startup environment. Local privileged Unix sockets MUST enforce peer credentials and filesystem access, not trust a caller-supplied username. Owner authentication occurs during setup, policy changes, or explicit high-risk approval—not every policy-allowed push.

PROPOSED CLI contract (not implemented commands): `policy validate`, `policy simulate`, `policy diff`, `policy apply`, `agent enroll`, `agent revoke`, `credential enroll`, `audit show`, and `doctor isolation`. Before applying policy, show effective permissions and widening changes. Keep the default profile small and intelligible; advanced rules may use validated declarative files. An agent-facing `request` command/tool may request attenuated grants but is not an operator CLI.

WebAuthn/OIDC and a dedicated web interface are future options. An OpenClaw/chat integration may display requests but MUST NOT be the sole trusted approval authority if the agent can modify that process or forge its inputs.

Policy changes MUST be versioned, validated, audited, and applied atomically. Agents MUST NOT edit policy, approve themselves, mint upstream credentials, or register new destinations. Changes that widen access SHOULD require an independent approver in multi-user deployments.

A policy rollback MUST NOT restore revoked capabilities or reset usage budgets. Break-glass access MUST use a separate identity, short expiry, explicit reason, and durable audit. Its presence is OPEN, not assumed.

## 12. Durable operations and audit

Use a state machine such as:

`received -> validated -> awaiting_approval/queued -> reserved -> dispatched -> succeeded/failed/outcome_unknown`

`cancelled`, `denied`, and `expired` are terminal only when no remote side effect can still occur. Keep approval and dispatch transitions transactional with usage reservations. Do not refund an ambiguous write automatically.

Idempotency keys MUST bind principal and a canonical payload digest. Reuse with different content MUST fail. Persist results across restart. Never promise exactly-once behavior across a provider API that lacks an appropriate atomic/idempotent primitive.

Persist write intent before dispatch. If durable local intent cannot be written, deny the operation. Persist outcomes after execution. If the remote write succeeds but local recording fails, recovery MUST treat it as uncertain and reconcile rather than retry blindly.

Audit fields: event ID, time, principal, capability ID, provider/repository IDs, operation, relevant refs/object IDs, policy revision, matched rule IDs, approval ID, operation digest, dispatch state, outcome, and safe correlation IDs.

Exclude tokens, private keys, signed URLs, packs, file contents, PR/MR bodies, arbitrary command output, and unsanitized provider errors. Repository names and commit IDs may still be sensitive metadata.

PROPOSED: append-only remote audit export with integrity checking and separate credentials. A local hash chain alone is not tamper-proof against a host attacker. Define allowed export lag and behavior when the export sink is unavailable. Retention, deletion, and audit-reader permissions are OPEN.

## 13. Deployment, resilience, and supply chain

- Separate service identities for agents, broker workers, operators, and audit export.
- Read-only application images; writable state and temporary mounts only where needed.
- No host root, privileged containers, container-runtime sockets, or agent workspace mounts.
- Enforce CPU, memory, process, request, queue, temporary-storage, decompression, and wall-clock limits.
- Execute repository parsing in a lower-privilege worker with no provider secrets and no outbound network.
- Pin dependencies and Git/parser versions. Produce SBOMs, signed release artifacts, and build provenance.
- Review upstream unYOLO changes before adoption. Never auto-update the authorization path without verification.
- Test database migrations, crash recovery, revocation persistence, backup restores, and rollback compatibility.
- Restore MUST NOT resurrect revoked grants or reset budgets. If freshness cannot be established, invalidate restored capabilities and require reissuance.
- Reject split-brain writes. Multi-node scheduling requires authoritative shared state or explicit single-writer fencing.
- Health/readiness endpoints MUST reveal no credentials or sensitive policy. Unhealthy authorization state MUST remove write readiness.
- Define patch SLAs, incident ownership, credential-rotation drills, and maintenance responsibilities.

Single-operator use in a shared local Linux VM is selected. Concurrency, repository size, availability target, latency target, RPO/RTO, and retention remain OPEN. Do not invent production SLAs before these are answered.

### 13.1 Same-VM Linux deployment contract

The VM boundary protects neither the broker from another root process nor agents from each other by itself. Use these additional boundaries:

- Dedicated non-login `git-broker` service user. Separate operator account and agent UIDs; one UID per independently trusted agent runtime where identity matters.
- Root-owned broker executable, dependencies, unit files, policy, and operator CLI. Agents cannot replace code the broker will execute.
- Broker-private credential/state directories and separate agent/operator Unix sockets. Use `SO_PEERCRED` or an equivalent authenticated channel. A socket path alone is not identity.
- No agent membership in sudo, docker, libvirt, disk, broker, or operator-privileged groups. No privileged capabilities, unrestricted setuid escape paths, host mounts, or upstream SSH-agent access.
- Restrict process inspection/ptrace and credential-bearing `/proc` access with platform controls such as Yama and hidepid where compatible. Validate effective access with adversarial tests.
- Harden systemd services with least privilege, `NoNewPrivileges`, filesystem restrictions, bounded resources, and a reviewed syscall/MAC profile where supported. Avoid assuming a generic unit template is sufficient.
- Keep parsing and advisory inference in unprivileged workers. Their IPC accepts only typed requests and narrow result schemas. A compromised worker cannot dispatch an unapproved write.
- Agent workspace directories and broker scratch space do not overlap. Independent clones are used where a shared Git directory would cross trust boundaries.
- Operator terminal sessions, shell history, environment, and CLI credential handles are inaccessible to agents. Unattended jobs cannot borrow human sudo authority.
- Use dedicated provider credentials unavailable through any other agent-visible account/keyring/config. A default OS account containing broad preexisting tokens defeats broker-only access.

The installer/doctor MUST refuse a safe-isolation verdict if agents have effective root, broker-account impersonation, an agent-controlled broker binary/config, or hypervisor/container control. If these restrictions cannot be met, move the broker into a separate VM that agents cannot administer. This is a requirement derived from the desired security boundary, not a claim that a second VM is already selected.

## 14. Release verification gates

Release requires documented evidence, not just test counts.

1. Every S1–S10 invariant maps to code, tests, and an owner.
2. Policy tests cover combinations of principal, provider, repository, operation, ref, expiry, budget, and approval.
3. Parser fuzzing covers malformed packets, refs, duplicate fields, pack bombs, thin packs, object format, multi-ref pushes, and unsupported capabilities.
4. Adversarial tests cover replay, copied tokens, audience mismatch, credential destination confusion, SSRF, redirects, malicious hooks/config, and operator impersonation.
5. Race tests cover concurrent pushes, retargeted reviews, expired approvals, policy changes, token revocation, and budget exhaustion at dispatch.
6. Recovery tests inject failures before and after every durable transition and remote dispatch.
7. GitHub and GitLab conformance tests run against disposable repositories with real provider rules. Verify both allowed and denied writes.
8. Canary credentials and sentinel secrets never appear in model-visible outputs, logs, telemetry, traces, or crash artifacts.
9. Deployment tests prove the agent cannot read secrets, access operator endpoints, modify policy, administer the broker, or use existing credentials to bypass it.
10. Load and resource-exhaustion tests meet the agreed limits without authorization degradation.
11. An independent security review covers custom provider execution and reused unYOLO code. Critical/high findings must be resolved before production; other exceptions require documented acceptance.
12. A limited-repository canary deployment completes before wider rollout. Rollback and emergency revocation are exercised.

Maintain a provider/operation support matrix. Unsupported or unverified cells remain disabled. No silent fallback or claim of GitHub/GitLab parity.

## 15. Decision register and remaining questions

Recorded operator answers (2026-10-17):

| Topic | Answer | Status |
| --- | --- | --- |
| Audience | Own agents | Confirmed |
| Deployment | Agents and broker in the same local VM, primarily Linux | Confirmed; OS isolation/agent privileges must be verified |
| Providers | Both GitHub and GitLab; probably GitLab Enterprise | Confirmed direction; exact instances/version pending |
| Interaction | Local MCP is acceptable; models generally use Git commands | Confirmed; native Git adapter recommended |
| Autonomy | Maximum autonomy for low-risk work; no routine password gates | Confirmed |
| Operations | Squashes, likely rebases/tags, deletion of nonprotected branches | Desired; safe semantics below need agreement |
| Production protections | No published-history rewrites, main pushes, or repository administration | Confirmed |
| CI/reviews | Not in place yet | Confirmed; cannot be assumed as gates |
| Storage | Probably protected local storage | Preferred direction; unlock model pending |
| Administration | CLI | Confirmed correction; separate operator authority required |
| Test repository | https://github.com/jiravani/git-credential-broker | Confirmed; public and initially empty |
| Optional component | Jev or Strands decision model | Confirmed correction; advisory integration proposed |

Do not repeat answered discovery questions. Resolve these remaining decisions:

Q1. Can agents run under separate unprivileged Linux users, with no sudo, broker-account access, Docker/libvirt group membership, hypervisor access, or shared secret directories? Which Linux distribution/hypervisor is planned? Same-VM isolation fails if agents retain host-administrator access.
Q2. Which human OS identity runs the operator CLI? Can the owner use a separate login while all agent runtimes stay unprivileged? No agent may reuse an unlocked operator session or credential.
Q3. Should decision-model evaluation remain entirely local (Strands Decider), or may minimized repository metadata be sent to hosted Jev? Start with shadow-mode metadata only; no source/diff upload without explicit authorization.
Q4. Which GitLab instance/version/edition and SSH transport must work first? Is provider API access available, or must first release be SSH-only?
Q5. Are local squash/rebase operations limited to unpublished disposable work? Should any remote-history rewrite remain a hard deny even on an agent-owned feature branch? Proposed answer: yes.
Q6. May automation delete only its own feature branches, with an exact-tip check and retained recovery reference? Which tag namespace is safe from deployments? Until known, tag creation stays disabled.
Q7. Can the VM require one owner unlock after boot, or must it restart unattended? What protects its disk, snapshots, backups, and encryption key?
Q8. Which agent clients and runtime isolation are required? Is normal Git compatibility a first-release requirement? What CPU/memory/repository size, concurrency, LFS, submodule, and SSH compatibility limits are needed?
Q9. Which production systems and credentials can agents currently reach outside Git? Git policy alone cannot prevent damage through those paths. Which paths will be removed or separately sandboxed?
Q10. What audit retention/recovery targets apply? Who maintains the tool and performs the independent security review? Should reusable unYOLO code be a dependency, pinned fork, or design reference?

Questions Q1, Q5, and Q7 are the next architecture/security decisions. Q2–Q4 and the remaining sizing questions can follow during discovery. Proposed defaults are not accepted security policy until reviewed.

## 16. Proposed milestones

- M0: Resolve architecture blockers; approve threat model and provider support matrix.
- M1: Review pinned unYOLO components and prove a small GitLab adapter against disposable repos.
- M2: Implement capability, policy, secret custody, operator separation, and durable audit controls.
- M3: Implement selected transports and provider operations; complete conformance and adversarial tests.
- M4: Independent review, isolation verification, recovery/load tests, and limited canary rollout.
- M5: Production release with signed artifacts, runbooks, monitoring, and maintenance ownership.

No credential migration, broker deployment, provider-rule changes, or replacement of existing agent authentication is authorized by this document alone. The operator supplied the GitHub repository for specification and disposable testing; publish only sanitized project material there.

## 16A. Jev and Strands Decider placement

Confirmed request: evaluate Jev or the Strands decision model. Strands Decider 2B is the likely intended Strands component. It is a decision model, not the separate Strands/Cedar authorization integration.

Jev returns typed decisions/probabilities through TypeSafe's API. Strands Decider supports local CPU/GPU inference and fixed-choice outputs. Neither is proof that a Git update is authorized or safe. A high confidence value is not a security guarantee.

### Recommended first integration

Keep the model outside the authorization path in shadow mode. Give it sanitized operation metadata after deterministic classification. It can label anomalies for the operator, categorize denials, identify candidate policy improvements, or score test cases. Models cannot reliably explain judgments in prose merely because they produce choice scores; generate UI explanations from deterministic facts and matched rule IDs.

Example advisory choices: `routine_feature_work`, `unusual_request`, `needs_owner_review`, `insufficient_context`. These are advisory categories, not effective allow/deny policy. Branch names, commit messages, and diffs remain untrusted and can carry prompt injection.

Flow:

`agent request -> deterministic parser/plan -> deterministic policy -> bounded executor`

`                                      -> redacted event -> optional Jev/Decider -> operator advisory`

- No model result can turn deny or unknown into allow, issue a grant, mark a ref unprotected, change a use budget, or approve itself.
- Exact ref matching, history ancestry, token lifetime, and budget arithmetic use ordinary deterministic code.
- An optional future model-based hold may only reduce already-allowed authority under an owner-approved policy. It introduces availability/false-positive tradeoffs and requires separate evaluation. It is not part of the initial profile.
- Model outage or timeout must not widen permissions. In advisory-only mode it must not block otherwise-authorized routine work.
- Run local inference under a separate unprivileged user, without credential-store, operator-socket, broker-memory, or policy-write access. Model weights and inference dependencies are not part of the privileged broker process.
- Hosted Jev requires explicit approval of the data egress profile. Do not send credentials, private URLs, source, or diffs by default.
- Pin model/version, question schema, and evaluation dataset. Record safe evaluation metrics separately from authoritative policy outcomes.
- Measure adversarial false negatives, false-positive review burden, calibration, latency, and resource use against a deterministic baseline. Do not cite unrelated public benchmarks as a Git-security validation.

Recommendation: if a local experiment is desired, try Strands Decider in a separate advisory process. Jev is a hosted comparison candidate. Neither is needed to make automatic feature-branch grants safe and convenient, and neither should be a required dependency for the first release.

## 17. Sources and provenance

Reviewed unYOLO commit: `fb6ae6f9afde9cd4de122695697af24441ad670a`.

- Project: https://github.com/osolmaz/unyolo
- Ownership boundaries: https://github.com/osolmaz/unyolo/blob/fb6ae6f9afde9cd4de122695697af24441ad670a/docs/OWNERSHIP.md
- Threat model: https://github.com/osolmaz/unyolo/blob/fb6ae6f9afde9cd4de122695697af24441ad670a/docs/security/THREAT_MODEL.md
- GitHub broker: https://github.com/osolmaz/unyolo/blob/fb6ae6f9afde9cd4de122695697af24441ad670a/brokers/github/README.md
- Shared Git parser: https://github.com/osolmaz/unyolo/tree/fb6ae6f9afde9cd4de122695697af24441ad670a/git/protocol
- Credential store: https://github.com/osolmaz/unyolo/blob/fb6ae6f9afde9cd4de122695697af24441ad670a/credential/store/store.go
- Jev introduction: https://docs.typesafe.ai/introduction.md
- Strands Decider primary announcement: https://strandsagents.com/blog/introducing-strands-decider/
- Strands Decider source: https://github.com/strands-labs/strands-decider
- GitHub token scope documentation: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app

GitLab behavior is a verification task, not an inherited unYOLO capability. Source review is not a certification or independent audit. All requirements beyond the confirmed list are proposed engineering constraints until reviewed and accepted.
