# Live GitHub verification — 2026-10-18

Result: **SSH and HTTPS broker paths passed.**

Target: `jiravani/git-credential-broker` only.
Implementation: `0084987bd335341d29be7d2560983dc563a4679b`.
Evidence: [machine-readable results](github-live-results.json).
Harness: [scripts/live_github_test.py](../scripts/live_github_test.py).

## Observed

For each transport, a real agent CLI process connected through the Unix socket
API to a real broker daemon. The broker used its vault credential to create a
new branch on GitHub. A second authorized operation advanced that branch.

- Dedicated repository deploy key authenticated over SSH.
- GitHub host keys came from the TLS-verified `https://api.github.com/meta` endpoint.
- User-supplied PAT authenticated HTTPS writes.
- CLI push created the intended feature ref at the exact planned commit.
- A fast-forward operation advanced it to the exact second commit.
- Identical request replay returned the same operation ID and result.
- A new request ID could not spend an already-used grant.
- Requests targeting main, the actual default branch, or a foreign namespace were denied.
- A valid full bundle proposing history rollback was denied at execution.
- Altering an authorized plan was denied.
- The feature ref still pointed to the second commit after rejection tests.
- All refs present before the test retained their original object IDs.
- Exactly two refs were added during the live test. No refs were deleted or force-updated.
- The daemon stopped and its two test sessions were revoked afterward.

The default branch is `feat/scoped-git-broker`, not `main`; both names were denied.
Negative tests used the broker boundary. They did not try a direct upstream
protected-branch push with the admin PAT. Provider-side rules are a separate control.

## Retained artifacts

- `broker-e2e/20261018-073518/ssh`
- `broker-e2e/20261018-073518/https`

These branches contain only empty test commits. They have no workflow files.
They are retained as evidence. Publishing this report uses a separate evidence branch;
it does not move the default branch.

Credentials were enrolled in an owner-only local test vault. Neither credentials
nor session bearer values are in the repository or report. The local vault key and
ciphertext remain under the same OS account; this is not production key isolation.

## Limits

This is real GitHub transport evidence, not a production security certification.
The host was macOS and both processes used the same UID. Cross-UID Linux isolation,
GitLab Enterprise transport, parser privilege separation, and aggregate resource
controls remain unverified release gates. No delete, tag, PR/MR merge, or repository
administration operation was tested against GitHub.

The earlier 143-test regression suite also passed after this live test.
Ruff and strict mypy include the new harness.

## Reproduction

Enroll test credentials as `ssh-test` and `https-test` in a private test vault.
Place TLS-verified GitHub host keys in that vault root's `known_hosts` file.
Use a fresh private root and an unused Unix socket path. Then run:

```sh
uv run python scripts/live_github_test.py \
  --root /private/test-root \
  --default-branch feat/scoped-git-broker \
  --report /private/github-live-results.json
```

This command performs real writes to new timestamped branches in the hard-coded
test repository. It must not be included in ordinary offline test runs.
