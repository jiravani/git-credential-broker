# Desktop Linux isolation verification

Result: **25/25 isolation checks passed; 143/143 regression tests passed**.
[Machine-readable evidence](linux-desktop-isolation-results.json).

Environment: disposable Docker container on the Desktop's Linux x86_64 kernel.
This is not a separate VM. It shares the host kernel.
No production credential, SSH private key, home directory, host Docker socket,
or production repository was mounted or copied into the container.

## Reproduce

```sh
docker build -f Dockerfile.isolation -t git-broker-isolation:20261018 .
docker run --rm --name git-broker-isolation-20261018 \
  --network none --read-only \
  --tmpfs /lab:rw,nosuid,nodev,size=128m \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --memory 1g --cpus 2 --pids-limit 128 \
  --security-opt no-new-privileges \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add KILL \
  git-broker-isolation:20261018
```

The root process is a trusted test controller. It needs listed capabilities to
create private fixtures, switch users, and stop the broker. It is not the agent.
Every child drops its entire capability bounding set and sets `no_new_privs`.
The agent has no effective, permitted, inheritable, ambient, or bounding capabilities.
The runtime has no external network. Build-time package downloads occur before testing.

Users: broker UID 21001; agent UID 21002; unrelated user UID 21003.
Only broker and authorized agent belong to the socket-access group.

## Controls exercised

- Authorized agent can use its session over the broker-owned group socket.
- An actual cross-UID feature push reaches a broker-owned disposable bare repository.
- A protected-branch push fails; the broker confirms only the feature ref exists.
- Agent cannot directly read the remote ref file to bypass the broker.
- Agent cannot read the vault key, ciphertext, policy, or fake plaintext credential.
- Agent cannot edit policy, replace the vault key, or unlink the socket.
- Unrelated user cannot connect to the socket or read the agent session.
- Agent cannot inspect broker process environment/memory, attach ptrace, or signal it.
- Agent cannot become root; capability sets are empty and no_new_privs is active.
- No Docker socket or SSH agent is available inside the container.
- Only loopback exists; direct public egress fails.
- Socket access alone cannot authenticate a request.
- Agent API does not expose owner policy administration.
- Full regression suite runs again as the unprivileged agent user.

## Scope and limits

These checks establish the observed permissions of this specific fixture.
They do not automatically apply the same controls to other Desktop services or agents.
Host administrator and kernel compromise are outside this boundary.
The socket authenticates bearer sessions; it does not bind sessions to peer UID.

Git parsing still runs as the broker UID. This test does NOT establish parser
privilege separation. A malicious native Git exploit could still reach credentials
in a deployed broker process's security domain. That remains a production blocker.

The whole container is network-disabled, including the broker. This proves absence
of agent egress here, not a production topology where only the broker may reach
GitHub/GitLab. The live GitHub tests were separate. GitLab Enterprise is not tested.
Cgroup and tmpfs bounds are configured but exhaustion behavior was not load-tested.
No kernel exploit, container escape, or comprehensive sandbox attack was attempted.

## Harness corrections

Initial harness runs stopped during setup, before security assertions:

- Permission mode must be set before transferring fixture ownership when the
  controller lacks CAP_FOWNER.
- Public installed source must be readable by test users; the build initially
  retained private source-directory modes from the development workspace.

The harness was corrected without relaxing agent privileges or private-state modes.
This new harness did not receive independent agent review: the reviewer runtime
failed before review started. Existing broker review evidence remains separate.
