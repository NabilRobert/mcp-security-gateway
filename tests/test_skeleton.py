"""Slice A: the thinnest end-to-end path. An agent lists and calls tools
through the gateway; the result is the upstream's; the audit log records
it and its chain verifies."""

import json
import shutil
from pathlib import Path

import pytest
from conftest import KEY_A, FakeUpstream, RunningGateway, agent, make_config, running_gateway
from mcp import Client

from mcp_gateway.app import connect_upstream
from mcp_gateway.audit import verify_chain
from mcp_gateway.config import GatewayConfig

pytestmark = pytest.mark.anyio

FS_SERVER = (
    Path(__file__).resolve().parents[2]
    / "agent-eval-harness/tools/fs-server/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
)
FIXTURE = Path(__file__).resolve().parents[2] / "agent-eval-harness/suites/fixtures/acme-shop"


def audit_lines(gw: RunningGateway) -> list[dict[str, object]]:
    return [json.loads(line) for line in gw.config.audit.path.read_text().splitlines()]


async def test_lists_only_allowed_tools(gateway: RunningGateway) -> None:
    async with agent(gateway.url(), KEY_A) as client:
        tools = await client.list_tools()
    assert sorted(t.name for t in tools.tools) == ["echo", "read"]


async def test_call_returns_the_upstreams_result(gateway: RunningGateway) -> None:
    async with Client(FakeUpstream().server()) as direct:
        expected = await direct.session.call_tool("echo", {"text": "hi"})
    async with agent(gateway.url(), KEY_A) as client:
        result = await client.session.call_tool("echo", {"text": "hi"})
    assert result.content == expected.content
    assert result.structured_content == expected.structured_content
    assert result.is_error == expected.is_error
    assert gateway.upstream.calls == [("echo", {"text": "hi"})]


async def test_audit_log_records_the_call_and_verifies(gateway: RunningGateway) -> None:
    async with agent(gateway.url(), KEY_A) as client:
        await client.session.call_tool("echo", {"text": "hi"})
    lines = audit_lines(gateway)
    assert [line["kind"] for line in lines] == ["start", "call", "result"]
    call, result = lines[1], lines[2]
    assert call["decision"] == "forwarding" and call["caller"] == "alpha" and call["tool"] == "echo"
    assert result["decision"] == "allowed" and result["call_id"] == call["call_id"]
    assert call["policy_sha256"] == gateway.config.policy_hash()
    assert verify_chain(gateway.config.audit.path) == []


@pytest.mark.skipif(not FS_SERVER.is_file() or shutil.which("node") is None, reason="filesystem server not installed")
async def test_real_filesystem_server_over_stdio(tmp_path: Path) -> None:
    """The walking skeleton as Phase 6 describes it: one stdio route, one key,
    a one-tool allow-list."""
    fixture = tmp_path / "acme-shop"
    shutil.copytree(FIXTURE, fixture)
    config = GatewayConfig.model_validate(
        {
            **make_config(tmp_path).model_dump(mode="json"),
            "upstreams": {"files": {"transport": "stdio", "command": "node", "args": [str(FS_SERVER), str(fixture)]}},
            "policies": {
                "reader": {"routes": {"files": {"tools": {"read_text_file": {}}}}},
                "echo-only": {"routes": {}},
            },
        }
    )
    async with running_gateway(config, connect_upstream) as base, agent(f"{base}/mcp/files/", KEY_A) as client:
        tools = await client.list_tools()
        result = await client.session.call_tool("read_text_file", {"path": "README.md"})
    assert [t.name for t in tools.tools] == ["read_text_file"]
    assert not result.is_error
    assert "acme-shop" in result.content[0].text  # type: ignore[union-attr]
    assert verify_chain(config.audit.path) == []
