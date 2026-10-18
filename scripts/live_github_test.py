"""Opt-in live GitHub checks. Creates new branches; never deletes or forces a ref.

Requires a pre-enrolled vault with slots `ssh-test` and `https-test`.
All agent requests use session capabilities, not provider credentials.
This harness runs under one OS account; it does not prove cross-UID isolation.
"""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

from git_broker.client import Client
from git_broker.files import atomic_write
from git_broker.models import OperationPlan
from git_broker.state import State

REMOTE = "https://github.com/jiravani/git-credential-broker.git"


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.PIPE)


def refs() -> dict[str, str]:
    return {line.split()[1]: line.split()[0] for line in git("ls-remote", "--refs", REMOTE).splitlines()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--default-branch", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    namespace = f"broker-e2e/{stamp}"
    before = refs()
    policy = {"version": 1, "repositories": {}, "principals": {}}
    repositories: dict[str, object] = {}
    principals: dict[str, object] = {}
    for backend in ["ssh", "https"]:
        repositories[backend] = {
            "backend": backend,
            "remote": ("ssh://git@github.com/jiravani/git-credential-broker.git"
                       if backend == "ssh" else REMOTE),
            "credential": backend + "-test", "username": "x-access-token",
            "known_hosts": str(root / "known_hosts"), "default_branch": args.default_branch,
            "protected": ["main", "master", "release/*", args.default_branch],
            "automation_reviewed": True,
        }
        principals[backend] = {"max_operations": 30, "rules": [{"repository": backend,
            "operations": ["read", "push"], "branches": [namespace + "/*"]}]}
    policy["repositories"] = repositories
    policy["principals"] = principals
    atomic_write(root / "policy.json", json.dumps(policy).encode())
    state = State(root)
    clients = {}
    for backend in repositories:
        session = state.issue_session(backend, 600, 30)
        path = root / (backend + ".session")
        atomic_write(path, str(session["token"]).encode())
        clients[backend] = Client(str(root / "broker.sock"), path)
    process = subprocess.Popen([sys.executable, "-m", "git_broker.cli", "--root", str(root),
        "serve", "--socket", str(root / "broker.sock")], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    results: list[dict[str, object]] = []
    expected_new: dict[str, str] = {}
    try:
        for _ in range(100):
            try:
                clients["ssh"].call({"action": "scope"})
                break
            except httpx.HTTPError:
                time.sleep(0.1)
        else:
            raise RuntimeError("daemon unavailable")
        for backend, client in clients.items():
            branch = namespace + "/" + backend
            work = root / ("work-" + backend + "-" + stamp)
            git("init", str(work))
            git("-c", "user.name=Broker test", "-c", "user.email=test@example.invalid",
                "commit", "--allow-empty", "-m", "Disposable broker transport test", cwd=work)

            def plan(old: str = "", work: Path = work, backend: str = backend,
                     branch: str = branch) -> tuple[dict[str, object], bytes]:
                bundle = work / (uuid.uuid4().hex + ".bundle")
                git("bundle", "create", str(bundle), "HEAD", cwd=work)
                payload = bundle.read_bytes()
                value = OperationPlan(operation="push", repository=backend, branch=branch,
                    expected_old=old, commit=git("rev-parse", "HEAD", cwd=work).strip(),
                    payload_digest=hashlib.sha256(payload).hexdigest())
                return value.model_dump(), payload

            def execute(value: dict[str, object], payload: bytes, client: Client = client) -> tuple[dict[str, object], dict[str, object]]:
                grant = client.call({"action": "grant", "plan": value})
                request = {"action": "execute", "plan": value, "grant": grant["token"],
                    "request_id": str(uuid.uuid4()), "payload": base64.b64encode(payload).decode()}
                return client.call(request), request

            def denied(request: dict[str, object], client: Client = client) -> None:
                try:
                    client.call(request)
                except httpx.HTTPStatusError as error:
                    assert error.response.status_code == 400
                else:
                    raise AssertionError("unsafe request was not denied")

            value, payload = plan()
            # Exercise actual agent CLI helper for initial provider push.
            output = subprocess.check_output([sys.executable, "-m", "git_broker.client",
                "--socket", str(root / "broker.sock"), "--token-file",
                str(root / (backend + ".session")), "--repository", backend, "--branch", branch],
                cwd=work, text=True, stderr=subprocess.PIPE)
            assert json.loads(output)["state"] == "succeeded"
            first = str(value["commit"])
            assert refs()["refs/heads/" + branch] == first
            git("-c", "user.name=Broker test", "-c", "user.email=test@example.invalid",
                "commit", "--allow-empty", "-m", "Fast-forward transport test", cwd=work)
            value, payload = plan(first)
            result, request = execute(value, payload)
            assert result["state"] == "succeeded"
            second = str(value["commit"])
            expected_new["refs/heads/" + branch] = second
            replay = client.call(request)
            assert replay["id"] == result["id"] and replay["state"] == "succeeded"
            denied({**request, "request_id": str(uuid.uuid4())})
            for protected in ["main", args.default_branch, "other-agent/task"]:
                denied({"action": "grant", "plan": {**value, "branch": protected}})
            changed = {**value, "expected_old": second, "commit": first}
            # Correct digest/full bundle for old commit; reject actual ancestry rollback.
            git("checkout", "--detach", first, cwd=work)
            rollback, old_payload = plan(second)
            grant = client.call({"action": "grant", "plan": rollback})
            denied({"action": "execute", "plan": rollback, "grant": grant["token"],
                "request_id": str(uuid.uuid4()), "payload": base64.b64encode(old_payload).decode()})
            grant = client.call({"action": "grant", "plan": changed})
            denied({"action": "execute", "plan": {**changed, "branch": branch + "-changed"},
                "grant": grant["token"], "request_id": str(uuid.uuid4()),
                "payload": base64.b64encode(payload).decode()})
            assert refs()["refs/heads/" + branch] == second
            results.append({"transport": backend, "branch": branch, "first": first, "final": second,
                "checks": ["CLI create", "fast-forward", "idempotent replay",
                           "spent grant denied", "protected/default/foreign branch denied",
                           "history rollback denied", "changed plan denied", "remote tip preserved"]})
        after = refs()
        assert all(after.get(ref) == oid for ref, oid in before.items())
        assert {ref: oid for ref, oid in after.items() if ref not in before} == expected_new
        args.report.write_text(json.dumps({"repository": REMOTE, "results": results,
            "existing_refs_unchanged": True, "new_refs": expected_new,
            "same_uid_test_only": True, "credentials_in_report": False}, indent=2) + "\n")
        print(json.dumps({"transports_passed": len(results), "existing_refs_unchanged": True}))
    finally:
        process.terminate()
        process.wait(timeout=15)


if __name__ == "__main__":
    main()
