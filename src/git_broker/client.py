"""Agent-side CLI and MCP adapter. Holds only a revocable broker session."""

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
import uuid
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

from .files import read_file


class Client:
    """Use a local Unix socket without ambient proxy settings."""

    def __init__(self, socket: str, token_file: Path) -> None:
        self.socket = socket
        self.token_file = token_file

    def call(self, request: dict[str, object]) -> dict[str, object]:
        token = read_file(self.token_file, 128).decode("ascii").strip()
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=self.socket), trust_env=False, timeout=600,
        ) as client:
            response = client.post("http://localhost/rpc", json=request,
                                   headers={"Authorization": f"Bearer {token}"})
            response.raise_for_status()
            result: dict[str, object] = response.json()
            return result


def main() -> None:
    """Run JSON CLI requests or expose the same typed service through stdio MCP."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--mcp", action="store_true")
    parser.add_argument("--repository", help="Broker repository ID for HEAD push")
    parser.add_argument("--branch", help="Explicit destination branch for HEAD push")
    parser.add_argument("--request", type=Path, help="JSON request file; omit for scope")
    args = parser.parse_args()
    client = Client(args.socket, args.token_file)
    if args.repository or args.branch:
        if not args.repository or not args.branch or args.mcp or args.request:
            parser.error("push needs repository and branch, without MCP/request")
        print(json.dumps(push_head(client, args.repository, args.branch)))
    elif args.mcp:
        mcp = FastMCP("Git credential broker")

        @mcp.tool()
        def broker_request(request: dict[str, object]) -> dict[str, object]:
            """Request scope, grant, execution, or caller-owned operation status."""
            return client.call(request)

        mcp.run(transport="stdio")
    else:
        request = json.loads(args.request.read_text()) if args.request else {"action": "scope"}
        print(json.dumps(client.call(request)))


def push_head(client: Client, repository: str, branch: str) -> dict[str, object]:
    """Upload immutable HEAD; the broker decides whether this is a permitted FF."""
    from .models import OperationPlan

    def execute(plan: OperationPlan, payload: bytes = b"") -> dict[str, object]:
        grant = client.call({"action": "grant", "plan": plan.model_dump()})
        return client.call({"action": "execute", "plan": plan.model_dump(),
                            "grant": grant["token"], "request_id": str(uuid.uuid4()),
                            "payload": base64.b64encode(payload).decode("ascii")})

    tip = execute(OperationPlan(operation="read", repository=repository, branch=branch))
    result = tip.get("result")
    if not isinstance(result, dict):
        raise ValueError("read outcome unknown; stop")
    with tempfile.TemporaryDirectory(prefix="broker-client-") as directory:
        bundle = Path(directory) / "head.bundle"
        # This process is agent-side, holds no upstream credential, and has only agent privileges.
        subprocess.run(["git", "bundle", "create", str(bundle), "HEAD"], check=True,
                       stdout=subprocess.DEVNULL, timeout=60)
        heads = subprocess.check_output(["git", "bundle", "list-heads", str(bundle)], timeout=10)
        commit = heads.decode("ascii").split()[0]
        if bundle.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("bundle exceeds client limit")
        payload = bundle.read_bytes()
    plan = OperationPlan(operation="push", repository=repository, branch=branch,
                         expected_old=str(result["commit"]), commit=commit,
                         payload_digest=hashlib.sha256(payload).hexdigest())
    return execute(plan, payload)


if __name__ == "__main__":
    main()
