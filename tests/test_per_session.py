"""Slice F: a stateful stdio upstream gets one process per MCP session
(ADR-010), so one agent's writes can't reach another's run (Spike 2)."""

import asyncio
import contextlib
import gc
import shutil
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from conftest import KEY_A, make_config, running_gateway
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer

from mcp_gateway.app import connect_upstream
from mcp_gateway.config import GatewayConfig, HttpUpstream, StdioUpstream

pytestmark = pytest.mark.anyio


class Counter:
    """Each opened upstream gets its own notebook; counts opens and closes."""

    def __init__(self) -> None:
        self.opened = 0
        self.closed = 0

    def connect(self) -> Any:
        @contextlib.asynccontextmanager
        async def open_one(name: str, upstream: HttpUpstream | StdioUpstream) -> AsyncIterator[Client]:  # noqa: ARG001
            self.opened += 1
            notes: list[str] = []
            mcp = MCPServer("stateful")

            @mcp.tool()
            def write(text: str) -> str:
                """Remember something."""
                notes.append(text)
                return "ok"

            @mcp.tool()
            def read() -> str:
                """What was remembered in this upstream."""
                return ",".join(notes)

            try:
                async with Client(mcp) as client:
                    yield client
            finally:
                self.closed += 1

        return open_one


def per_session_config(tmp_path: Path) -> GatewayConfig:
    data = make_config(
        tmp_path,
        policies={"reader": {"routes": {"fake": {"tools": {"write": {}, "read": {}}}}}, "echo-only": {"routes": {}}},
    ).model_dump(mode="json")
    data["upstreams"]["fake"] = {"transport": "stdio", "command": "unused", "per_session": True}
    return GatewayConfig.model_validate(data)


@contextlib.asynccontextmanager
async def legacy_agent(url: str) -> AsyncIterator[Client]:
    """A session-based client, as Inspect is (initialize handshake)."""
    async with (
        httpx2.AsyncClient(headers={"Authorization": f"Bearer {KEY_A}"}, timeout=30) as http,
        Client(streamable_http_client(url, http_client=http), mode="legacy") as client,
    ):
        yield client


def text(result: Any) -> str:
    return result.content[0].text if result.content else ""


async def test_each_session_gets_its_own_upstream(tmp_path: Path) -> None:
    counter = Counter()
    async with running_gateway(per_session_config(tmp_path), counter.connect()) as base:
        url = f"{base}/mcp/fake/"
        async with legacy_agent(url) as first, legacy_agent(url) as second:
            await first.session.call_tool("write", {"text": "first's secret"})
            assert text(await first.session.call_tool("read", {})) == "first's secret"
            assert text(await second.session.call_tool("read", {})) == ""  # nothing leaked
        # one probe at start, then one per session
        assert counter.opened == 3


async def test_an_ended_session_stops_its_upstream(tmp_path: Path) -> None:
    counter = Counter()
    async with running_gateway(per_session_config(tmp_path), counter.connect()) as base:
        async with legacy_agent(f"{base}/mcp/fake/") as client:
            await client.session.call_tool("read", {})
        for _ in range(100):  # the client closed its session; the SDK drops it
            gc.collect()
            if counter.closed == 2:  # the probe, and this session's upstream
                break
            await asyncio.sleep(0.05)
        assert counter.closed == 2


async def test_a_sessionless_client_is_refused_on_a_per_session_route(tmp_path: Path) -> None:
    counter = Counter()
    async with running_gateway(per_session_config(tmp_path), counter.connect()) as base:
        async with (
            httpx2.AsyncClient(headers={"Authorization": f"Bearer {KEY_A}"}, timeout=30) as http,
            Client(streamable_http_client(f"{base}/mcp/fake/", http_client=http)) as client,
        ):
            if (client.session.protocol_version or "") < "2026-07-28":
                pytest.skip("this SDK negotiated a session-based protocol")
            with pytest.raises(Exception, match="session-based"):
                await client.session.call_tool("read", {})
    assert counter.opened == 1  # only the start-up probe


HARNESS = Path(__file__).resolve().parents[2] / "agent-eval-harness"
FS_SERVER = HARNESS / "tools/fs-server/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"


@pytest.mark.skipif(not FS_SERVER.is_file() or shutil.which("node") is None, reason="filesystem server not installed")
async def test_the_harness_launcher_gives_each_session_a_fresh_fixture(tmp_path: Path) -> None:
    """The real case: the harness's own launcher copies the fixture per
    process, so a write in one session never shows in the next."""
    data = per_session_config(tmp_path).model_dump(mode="json")
    data["upstreams"]["fake"] = {
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-m", "agent_eval.fs_server", str(HARNESS / "suites/fixtures/acme-shop")],
        "cwd": str(HARNESS),
        "per_session": True,
    }
    data["policies"]["reader"]["routes"]["fake"]["tools"] = {"write_file": {}, "read_text_file": {}}
    config = GatewayConfig.model_validate(data)
    async with running_gateway(config, connect_upstream) as base:
        url = f"{base}/mcp/fake/"
        async with legacy_agent(url) as first:
            await first.session.call_tool("write_file", {"path": "README.md", "content": "pwned"})
            assert text(await first.session.call_tool("read_text_file", {"path": "README.md"})) == "pwned"
        async with legacy_agent(url) as second:
            assert "acme-shop" in text(await second.session.call_tool("read_text_file", {"path": "README.md"}))
