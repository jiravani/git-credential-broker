"""Owner-only administration. Agent identities must not have access to this state."""

import argparse
import asyncio
import getpass
import json
import os
import socket
import stat
from pathlib import Path
from typing import Literal, cast

import uvicorn

from .errors import BrokerError, Denied
from .executor import GitExecutor
from .files import atomic_write, private_directory, read_file
from .policy import FilePolicy
from .server import AgentAPI
from .service import Broker
from .state import State
from .vault import Vault


def main() -> None:
    """Administer standing policy and start the broker under a dedicated account."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    apply = sub.add_parser("policy-apply")
    apply.add_argument("file", type=Path)
    enroll = sub.add_parser("credential-set")
    enroll.add_argument("name")
    enroll.add_argument("kind", choices=["ssh", "https"])
    enroll.add_argument("--file", type=Path)
    issue = sub.add_parser("session-issue")
    issue.add_argument("principal")
    issue.add_argument("--out", type=Path, required=True)
    revoke = sub.add_parser("session-revoke")
    revoke.add_argument("id")
    sub.add_parser("audit")
    serve = sub.add_parser("serve")
    serve.add_argument("--socket", required=True, type=Path)
    serve.add_argument("--allow-local-test", action="store_true")
    serve.add_argument("--socket-gid", type=int, help="Owner-managed agent group ID")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        run(args)
    except (BrokerError, OSError, ValueError):
        parser.exit(1, "Broker refused operation; check private configuration and audit.\n")


def run(args: argparse.Namespace) -> None:
    root = args.root.absolute()
    private_directory(root)
    state = State(root)
    policy = FilePolicy(root / "policy.json")
    if args.command == "init":
        Vault.local(root / "vault", initialize=True)
        print("Initialized private local-key profile. No policy or provider access enabled.")
    elif args.command == "policy-apply":
        print(policy.apply(read_file(args.file, 1_048_576, secret=False), root))
    elif args.command == "credential-set":
        value = (read_file(args.file, 65536) if args.file
                 else getpass.getpass("Provider token: ").encode())
        Vault.local(root / "vault").put(args.name, cast(Literal["ssh", "https"], args.kind), value)
        print("Credential stored.")
    elif args.command == "session-issue":
        principal = policy.load().principals.get(args.principal)
        if principal is None or not principal.enabled:
            raise Denied("unknown principal")
        session = state.issue_session(args.principal, principal.max_session_seconds,
                                      principal.max_operations)
        atomic_write(args.out, str(session.pop("token")).encode(), replace=False)
        print(json.dumps(session))
    elif args.command == "session-revoke":
        print(json.dumps({"revoked": state.revoke(args.id)}))
    elif args.command == "audit":
        print(json.dumps(state.audit()))
    elif args.command == "serve":
        config = policy.load()
        if not args.allow_local_test and any(
            repo.backend == "local_test" for repo in config.repositories.values()
        ):
            raise Denied("test transport disabled")
        if args.socket.exists() or args.socket.is_symlink():
            raise Denied("socket already exists; inspect stale socket manually")
        broker = Broker(state, policy, Vault.local(root / "vault"),
                        GitExecutor(root / "executor", allow_local_test=args.allow_local_test,
                                    max_bundle_bytes=config.max_bundle_bytes), root)
        parent = args.socket.parent.stat()
        if (args.socket.parent.is_symlink() or parent.st_uid != os.getuid()
                or parent.st_mode & 0o022 or not stat.S_ISDIR(parent.st_mode)):
            raise Denied("socket parent must be owner-controlled and not group writable")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(args.socket))
            if args.socket_gid is not None:
                os.chown(args.socket, -1, args.socket_gid)
                os.chmod(args.socket, 0o660)
            else:
                os.chmod(args.socket, 0o600)
            listener.listen(8)
            listener.setblocking(False)
            config_http = uvicorn.Config(AgentAPI(broker), access_log=False,
                                         log_level="warning", limit_concurrency=8)
            asyncio.run(uvicorn.Server(config_http).serve(sockets=[listener]))


if __name__ == "__main__":
    main()
