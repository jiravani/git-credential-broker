"""Exercise real process, Unix-socket, CLI, MCP, and disposable Git boundaries."""

import asyncio
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from git_broker.client import Client


def test_cli_socket_push_and_mcp(tmp_path: Path) -> None:
    def run(*args: str, cwd: Path | None = None) -> str:
        return subprocess.check_output(list(args), cwd=cwd, text=True, stderr=subprocess.PIPE)

    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    run("git", "init", "--bare", str(remote))
    run("git", "init", str(work))
    (work / "README").write_text("disposable integration test\n")
    run("git", "add", "README", cwd=work)
    run("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-m", "Initial", cwd=work)
    root = tmp_path / "state"
    prefix = [sys.executable, "-m", "git_broker.cli", "--root", str(root)]
    run(*prefix, "init")
    config = tmp_path / "policy.json"
    config.write_text(json.dumps({"version": 1, "repositories": {"demo": {
        "backend": "local_test", "remote": str(remote), "automation_reviewed": True,
    }}, "principals": {"agent": {"rules": [{"repository": "demo",
        "operations": ["read", "push"], "branches": ["agents/*", "main"]}]}}}))
    run(*prefix, "policy-apply", str(config))
    token = tmp_path / "session.token"
    run(*prefix, "session-issue", "agent", "--out", str(token))
    sock = tmp_path / "broker.sock"
    process = subprocess.Popen([*prefix, "serve", "--socket", str(sock), "--allow-local-test"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        client = Client(str(sock), token)
        for _ in range(100):
            try:
                assert client.call({"action": "scope"})["principal"] == "agent"
                break
            except Exception:
                if process.poll() is not None:
                    pytest.fail("broker failed to start")
                time.sleep(0.05)
        else:
            pytest.fail("broker socket not ready")
        assert stat.S_IMODE(sock.stat().st_mode) == 0o600
        client_cmd = [sys.executable, "-m", "git_broker.client", "--socket", str(sock),
                      "--token-file", str(token)]
        result = json.loads(run(*client_cmd, "--repository", "demo", "--branch", "agents/test",
                                cwd=work))
        assert result["state"] == "succeeded"
        head = run("git", "rev-parse", "HEAD", cwd=work).strip()
        assert run("git", "--git-dir", str(remote), "rev-parse", "refs/heads/agents/test").strip() == head
        with pytest.raises(subprocess.CalledProcessError):
            run(*client_cmd, "--repository", "demo", "--branch", "main", cwd=work)
        refs = run("git", "--git-dir", str(remote), "show-ref")
        assert "refs/heads/main" not in refs

        async def mcp_smoke() -> None:
            params = StdioServerParameters(command=sys.executable,
                args=["-m", "git_broker.client", "--socket", str(sock), "--token-file", str(token),
                      "--mcp"], env=dict(os.environ))
            async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                assert [tool.name for tool in listed.tools] == ["broker_request"]
                response = await session.call_tool("broker_request", {"request": {"action": "scope"}})
                assert not response.isError

        asyncio.run(mcp_smoke())
    finally:
        process.terminate()
        process.communicate(timeout=10)
