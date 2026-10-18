"""Adversarial checks for the local authenticated transport boundary."""

import asyncio
import json
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from git_broker.executor import Credential
from git_broker.models import BrokerConfig, OperationPlan, Principal, Repository, Rule
from git_broker.policy import FilePolicy
from git_broker.server import AgentAPI, RequestBody
from git_broker.service import Broker
from git_broker.state import State
from git_broker.vault import Vault


class TransportExecutor:
    """A harmless executor that records whether HTTP input reaches dispatch."""

    def __init__(self) -> None:
        self.calls = 0

    def execute(
        self, repository: Repository, plan: OperationPlan, payload: bytes,
        credential: Credential | None,
    ) -> dict[str, object]:
        """Return fixed metadata without network or shell operations."""
        self.calls += 1
        return {"commit": "a" * 40}


@pytest.fixture
def api_context(tmp_path: Path) -> tuple[AgentAPI, str, TransportExecutor]:
    """Create an authentic policy/state/vault stack with a harmless executor."""
    state = State(tmp_path / "broker")
    config = BrokerConfig(
        repositories={"repo": Repository(
            backend="local_test", remote="/unused.git", automation_reviewed=True,
        )},
        principals={"alice": Principal(rules=[Rule(
            repository="repo", operations=["read"], branches=["feature/*"],
        )])},
    )
    path = state.root / "policy.json"
    path.write_text(config.model_dump_json())
    path.chmod(0o600)
    executor = TransportExecutor()
    broker = Broker(state, FilePolicy(path), Vault(state.root / "vault", b"k" * 32),
                    executor, state.root)
    token = str(state.issue_session("alice", 60, 5)["token"])
    return AgentAPI(broker, max_body=4096), token, executor


@pytest.mark.parametrize("headers", [
    [], [("authorization", "Bearer bogus")], [("authorization", "Basic abc")],
    [("authorization", "Bearer ")],
])
async def test_invalid_transport_auth_denied(
    api_context: tuple[AgentAPI, str, TransportExecutor], headers: list[tuple[str, str]],
) -> None:
    """No agent API operation is available without one valid bearer session."""
    app, _, executor = api_context
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://broker") as c:
        response = await c.post("/rpc", json={"action": "scope"}, headers=headers)
    assert response.status_code == 400
    assert executor.calls == 0


@pytest.mark.parametrize("attack", ["duplicate-auth", "browser-origin", "duplicate-fields",
                                         "oversize", "invalid-json", "unknown-field"])
async def test_ambiguous_or_unbounded_requests_denied(
    api_context: tuple[AgentAPI, str, TransportExecutor], attack: str,
) -> None:
    """Reject browser calls, parser ambiguity, and envelope resource attacks."""
    app, token, executor = api_context
    headers = [("authorization", f"Bearer {token}")]
    body = b'{"action":"scope"}'
    if attack == "duplicate-auth":
        headers.append(("authorization", f"Bearer {token}"))
    elif attack == "browser-origin":
        headers.append(("origin", "https://attacker.invalid"))
    elif attack == "duplicate-fields":
        body = b'{"action":"scope","action":"scope"}'
    elif attack == "oversize":
        body = b" " * 4097
    elif attack == "invalid-json":
        body = b'{"action":'
    else:
        body = b'{"action":"scope","credential":"CANARY-SENSITIVE-INPUT"}'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://broker") as c:
        response = await c.post("/rpc", content=body, headers=headers)
    assert response.status_code == 400
    assert token not in response.text
    assert "CANARY" not in response.text
    assert executor.calls == 0


@pytest.mark.parametrize("action", ["policy-apply", "credential-set", "session-issue",
                                    "session-revoke", "shell", "audit", "admin"])
async def test_owner_actions_unreachable_from_agent_api(
    api_context: tuple[AgentAPI, str, TransportExecutor], action: str,
) -> None:
    """Valid agent authentication grants no operator-plane authority."""
    app, token, executor = api_context
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://broker") as c:
        response = await c.post("/rpc", json={"action": action},
                                headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 400
    assert executor.calls == 0


async def test_http_grant_execute_and_replay(
    api_context: tuple[AgentAPI, str, TransportExecutor],
) -> None:
    """The real transport preserves single-use grant and idempotency boundaries."""
    app, token, executor = api_context
    plan = {"operation": "read", "repository": "repo", "branch": "feature/alice"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://broker",
                                headers={"authorization": f"Bearer {token}"}) as c:
        response = await c.post("/rpc", json={"action": "grant", "plan": plan})
        assert response.status_code == 200
        grant = response.json()["token"]
        request = {"action": "execute", "plan": plan, "grant": grant, "request_id": "once"}
        first = await c.post("/rpc", json=request)
        second = await c.post("/rpc", json=request)
        replay = await c.post("/rpc", json={**request, "request_id": "twice"})
    assert first.status_code == second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert replay.status_code == 400
    assert executor.calls == 1


async def test_revoked_session_rejected_over_transport(
    api_context: tuple[AgentAPI, str, TransportExecutor],
) -> None:
    """Previously valid authentication is checked again on the next request."""
    app, token, executor = api_context
    identity = app.broker.state.authenticate(token)
    app.broker.state.revoke(str(identity["id"]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://broker") as c:
        response = await c.post("/rpc", json={"action": "scope"},
                                headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 400
    assert executor.calls == 0


async def test_slow_body_blocks_second_request(
    api_context: tuple[AgentAPI, str, TransportExecutor],
) -> None:
    """Admission bounds body readers, not just dispatched executor calls."""
    app, token, _ = api_context
    ready, release = asyncio.Event(), asyncio.Event()

    async def stream() -> "AsyncIterator[bytes]":
        ready.set()
        await release.wait()
        yield json.dumps({"action": "scope"}).encode()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://broker",
                                headers={"authorization": f"Bearer {token}"}) as c:
        pending = asyncio.create_task(c.post("/rpc", content=stream()))
        await ready.wait()
        blocked = await c.post("/rpc", json={"action": "scope"})
        assert blocked.status_code == 429
        release.set()
        assert (await pending).status_code == 200


async def test_cancelled_request_does_not_reopen_worker_admission(
    api_context: tuple[AgentAPI, str, TransportExecutor], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancelled ASGI handler cannot bypass the still-running worker limit."""
    app, token, _ = api_context
    started, release = threading.Event(), threading.Event()

    def stalled(session: str, data: RequestBody) -> dict[str, object]:
        started.set()
        if not release.wait(5):
            raise RuntimeError("test worker timeout")
        return {"ok": True}

    monkeypatch.setattr(app, "dispatch", stalled)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://broker",
                                headers={"authorization": f"Bearer {token}"}) as c:
        pending = asyncio.create_task(c.post("/rpc", json={"action": "scope"}))
        try:
            assert await asyncio.to_thread(started.wait, 2)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert app.busy
            blocked = await c.post("/rpc", json={"action": "scope"})
            assert blocked.status_code == 429
        finally:
            release.set()
        async with asyncio.timeout(2):
            while app.busy:
                await asyncio.sleep(0.001)


async def test_real_uds_mcp_scope_smoke(
    api_context: tuple[AgentAPI, str, TransportExecutor], tmp_path: Path,
) -> None:
    """Launch real UDS and stdio MCP processes; verify socket mode and hidden token."""
    app, token, _ = api_context
    root = app.broker.root
    Vault.local(root / "vault", initialize=True)
    token_file = tmp_path / "agent.token"
    token_file.write_text(token)
    token_file.chmod(0o600)
    # Unix socket path limits require a deliberately short owner-only temporary path.
    with tempfile.TemporaryDirectory(prefix="gb-review-") as temporary:
        socket_path = Path(temporary) / "api.sock"
        process = subprocess.Popen(
            [sys.executable, "-m", "git_broker.cli", "--root", str(root), "serve",
             "--socket", str(socket_path), "--allow-local-test"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        try:
            async with asyncio.timeout(10):
                while not socket_path.exists():
                    if process.poll() is not None:
                        raise AssertionError("broker daemon failed to start")
                    await asyncio.sleep(0.02)
            assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600
            server = StdioServerParameters(
                command=sys.executable,
                args=["-m", "git_broker.client", "--socket", str(socket_path),
                      "--token-file", str(token_file), "--mcp"],
            )
            async with stdio_client(server) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listing = await session.list_tools()
                    assert [tool.name for tool in listing.tools] == ["broker_request"]
                    result = await session.call_tool("broker_request", {"request": {"action": "scope"}})
                    assert not result.isError
                    rendered = result.model_dump_json()
                    assert "alice" in rendered
                    assert token not in rendered
                    assert "credential" not in listing.model_dump_json().lower()
        finally:
            process.terminate()
            process.wait(timeout=10)
            if process.stderr:
                process.stderr.close()
