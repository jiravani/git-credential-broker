# Agent Git Access Broker

Design-stage security tool for agents working with GitHub and GitLab.

The owner sets policy once. Agents request limited read/write capabilities. The broker automatically authorizes matching low-risk operations and keeps upstream credentials private. Allowed pushes do not require an owner login each time.

## Status

This repository currently contains a specification, not a production implementation. No enforcement service is deployed by these files.

Read [SPEC.md](SPEC.md) for the threat model, standing-policy workflow, proposed operation profile, open decisions, and release gates.

## Intended boundary

- Broker and agents initially share a local Linux VM, under separate protected OS identities. Agents must not have root, sudo, or control of the broker service.
- Agent capabilities are limited by repository, operation, ref, expiry, and use count.
- No protected/default-branch pushes, published-history rewrites, or repository administration under the initial agent profile.
- Owner administration uses a CLI. Local MCP and a proposed native Git adapter use the same policy engine.
- Jev/Strands Decider may provide advisory classification; deterministic rules alone grant authority.
- SSH keys remain inside the broker. They are not replaced with agent-accessible copies.
- Worktrees are not security sandboxes. Production access outside Git needs separate controls.

## Design basis

The specification references [unYOLO](https://github.com/osolmaz/unyolo) at an exact reviewed commit. It does not imply endorsement, an independent security audit, or existing GitLab support. No upstream implementation code is copied into this repository.

Protected local storage, agent convenience, and automatic low-risk grants are design goals. Unanswered security decisions remain explicit; passing prototype tests is not a production certification.
