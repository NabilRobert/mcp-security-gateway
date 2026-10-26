"""Slice D: the gateway passes results through unchanged (Phase 3: transparent
apart from filtering), and an HTTP upstream gets its own credential, never
the agent's (Phase 3: the agent never holds the upstream credential)."""

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from conftest import KEY_A, agent, free_port, in_memory, make_config, running_gateway
from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent

from mcp_gateway.app import connect_upstream
from mcp_gateway.config import GatewayConfig

pytestmark = pytest.mark.anyio

STAMP = "io.modelcontextprotocol/serverInfo"
UPSTREAM_KEY = "upstream-only-key-the-agent-never-sees-0123456789"


def rich_upstream() -> MCPServer:
    mcp = MCPServer("rich-upstream")

    @mcp.tool()
    def stats(n: int) -> dict[str, Any]:
        """Structured output."""
        return {"n": n, "squares": [i * i for i in range(n)], "label": "ünïcode ✓"}

    @mcp.tool()
    def broken() -> str:
        """An error result: normal feedback, not a transport failure."""
        raise ToolError("the upstream refused this")

    @mcp.tool()
    def with_meta() -> CallToolResult:
        """A result carrying its own _meta and several content blocks."""
        return CallToolResult(
            content=[TextContent(type="text", text="one"), TextContent(type="text", text="two")],
            structured_content={"ok": True},
            _meta={"example.com/trace": "abc"},  # type: ignore[call-arg]
        )

    return mcp


def without_stamp(model: Any) -> Any:
    """JSON form, minus the SDK's per-connection serverInfo stamp, which
    names whichever server is on that connection (Spike 1)."""
    data = model.model_dump(mode="json", by_alias=True, exclude_none=True)
    meta = data.get("_meta")
    if isinstance(meta, dict):
        meta.pop(STAMP, None)
        if not meta:
            del data["_meta"]
    return data


def config_allowing_all(tmp_path: Path, tools: list[str]) -> GatewayConfig:
    return make_config(
        tmp_path,
        policies={
            "reader": {"routes": {"fake": {"tools": {t: {} for t in tools}}}},
            "echo-only": {"routes": {}},
        },
    )


async def test_results_pass_through_unchanged(tmp_path: Path) -> None:
    tools = ["stats", "broken", "with_meta"]
    fake: Any = type("Fake", (), {"server": staticmethod(rich_upstream)})()
    calls = [("stats", {"n": 4}), ("broken", {}), ("with_meta", {})]
    async with Client(rich_upstream()) as direct:
        expected_tools = without_stamp(await direct.list_tools())
        expected = [without_stamp(await direct.session.call_tool(t, a)) for t, a in calls]
    async with (
        running_gateway(config_allowing_all(tmp_path, tools), in_memory(fake)) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as client,
    ):
        assert without_stamp(await client.list_tools()) == expected_tools
        got = [without_stamp(await client.session.call_tool(t, a)) for t, a in calls]
    assert got == expected
    assert got[1]["isError"] is True and got[2]["_meta"] == {"example.com/trace": "abc"}


# --- an HTTP upstream gets its own key, never the agent's --------------------


class RecordingAuth:
    """In front of the fake HTTP upstream: requires the upstream's own key and
    records every Authorization header it receives."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.seen: list[str] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            header = dict(scope["headers"]).get(b"authorization", b"").decode()
            self.seen.append(header)
            if header != f"Bearer {UPSTREAM_KEY}":
                await send({"type": "http.response.start", "status": 401, "headers": []})
                await send({"type": "http.response.body", "body": b""})
                return
        await self.app(scope, receive, send)


@contextlib.asynccontextmanager
async def http_upstream() -> AsyncIterator[tuple[str, RecordingAuth]]:
    recorder = RecordingAuth(rich_upstream().streamable_http_app())
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(recorder, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}/mcp", recorder
    finally:
        server.should_exit = True
        await task


async def test_the_upstream_gets_its_own_key_and_never_the_agents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_UPSTREAM_KEY", UPSTREAM_KEY)
    async with http_upstream() as (url, recorder):
        config = GatewayConfig.model_validate(
            {
                **config_allowing_all(tmp_path, ["stats"]).model_dump(mode="json"),
                "upstreams": {"fake": {"transport": "http", "url": url, "auth_env": "FAKE_UPSTREAM_KEY"}},
            }
        )
        async with running_gateway(config, connect_upstream) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
            result = await client.session.call_tool("stats", {"n": 2})
    assert not result.is_error
    assert recorder.seen and set(recorder.seen) == {f"Bearer {UPSTREAM_KEY}"}
    assert not any(KEY_A in header for header in recorder.seen)


async def test_a_wrong_upstream_credential_fails_at_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_gateway.config import ConfigError

    monkeypatch.setenv("FAKE_UPSTREAM_KEY", "not-the-right-one")
    async with http_upstream() as (url, _):
        config = GatewayConfig.model_validate(
            {
                **config_allowing_all(tmp_path, ["stats"]).model_dump(mode="json"),
                "upstreams": {"fake": {"transport": "http", "url": url, "auth_env": "FAKE_UPSTREAM_KEY"}},
            }
        )
        with pytest.raises(ConfigError, match="unreachable"):
            async with running_gateway(config, connect_upstream):
                pass


# --- local only: Spike 1's replay against the real servers --------------------

LOCAL = os.environ.get("MCP_GATEWAY_LOCAL_TESTS") == "1"


FS_TOOLS = [
    "read_file", "read_text_file", "read_media_file", "read_multiple_files", "write_file", "edit_file",
    "create_directory", "list_directory", "list_directory_with_sizes", "directory_tree", "move_file",
    "search_files", "get_file_info", "list_allowed_directories",
]  # fmt: skip
BACKBONE_TOOLS = ["list_tables", "describe_table", "sample_rows", "run_query"]


@pytest.mark.skipif(not LOCAL, reason="set MCP_GATEWAY_LOCAL_TESTS=1 (needs the harness repro stack and fs server)")
async def test_recorded_calls_replay_identically_against_the_real_servers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spike 1, kept as a test: the recorded calls give identical results
    direct and through the gateway, for both real upstreams."""
    import shutil
    import sys

    from mcp import StdioServerParameters

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "spikes"))
    import s1_transparency as s1  # pyright: ignore[reportMissingImports]

    backbone_key: str = s1.local_backbone_key()
    monkeypatch.setenv("MCP_BACKBONE_LOCAL_KEY", backbone_key)
    fixture = tmp_path / s1.FIXTURE.name
    shutil.copytree(s1.FIXTURE, fixture)
    fs_args = [str(s1.FS_JS), str(fixture)]
    config = GatewayConfig.model_validate(
        {
            **make_config(tmp_path).model_dump(mode="json"),
            "upstreams": {
                "pagila": {"transport": "http", "url": s1.PAGILA_URL, "auth_env": "MCP_BACKBONE_LOCAL_KEY"},
                "files": {"transport": "stdio", "command": "node", "args": fs_args},
            },
            "policies": {
                "reader": {
                    "routes": {
                        "pagila": {"tools": {t: {} for t in BACKBONE_TOOLS}},
                        "files": {"tools": {t: {} for t in FS_TOOLS}},
                    }
                },
                "echo-only": {"routes": {}},
            },
        }
    )
    async with running_gateway(config, connect_upstream) as base:
        async with s1.http_client(s1.PAGILA_URL, backbone_key) as direct, agent(f"{base}/mcp/pagila/", KEY_A) as via:
            assert await s1.compare("pagila", direct, via, s1.recorded_calls({"pagila"}))
        async with (
            Client(StdioServerParameters(command="node", args=fs_args)) as direct,
            s1.http_client(f"{base}/mcp/files/", KEY_A, mode="legacy") as via,
        ):
            fs_calls = s1.recorded_calls({"filesystem", "filesystem-v2"})
            assert await s1.compare("files", direct, via, fs_calls, strip=False)
