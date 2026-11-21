"""Limits on what an upstream can cost the gateway: processes per session
(capped per key and in total), how long an answer may take, and how large an
HTTP answer may be."""

import asyncio
import contextlib
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
import uvicorn
from conftest import KEY_A, KEY_B, FakeUpstream, agent, free_port, in_memory, make_config, running_gateway
from limits_server import build
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent
from test_per_session import Counter, legacy_agent, per_session_config

from mcp_gateway.app import connect_upstream
from mcp_gateway.config import GatewayConfig, UpstreamSessionLimits
from mcp_gateway.upstreams import CappedTransport, PerSessionUpstreams, SessionBudget

pytestmark = pytest.mark.anyio

LIMITS_SERVER = Path(__file__).with_name("limits_server.py")


@contextlib.asynccontextmanager
async def fake_client() -> AsyncIterator[Any]:
    yield object()


@contextlib.asynccontextmanager
async def sessions(max_total: int, max_per_caller: int) -> AsyncIterator[PerSessionUpstreams]:
    limits = UpstreamSessionLimits(max_total=max_total, max_per_caller=max_per_caller)
    async with anyio.create_task_group() as tasks:
        upstreams = PerSessionUpstreams("r", fake_client, tasks, SessionBudget(limits))
        try:
            yield upstreams
        finally:
            upstreams.close_all()


# --- processes per session -----------------------------------------------------


async def test_a_key_past_its_session_cap_starts_no_upstream() -> None:
    async with sessions(max_total=10, max_per_caller=2) as upstreams:
        await upstreams.for_session("s1", "alpha")
        await upstreams.for_session("s2", "alpha")
        with pytest.raises(MCPError, match="this key already has 2 upstream sessions open"):
            await upstreams.for_session("s3", "alpha")
        await upstreams.for_session("s4", "bravo")  # another key isn't affected
        assert upstreams.started == 3


async def test_the_total_session_cap_holds_across_keys() -> None:
    async with sessions(max_total=2, max_per_caller=5) as upstreams:
        await upstreams.for_session("s1", "alpha")
        await upstreams.for_session("s2", "bravo")
        with pytest.raises(MCPError, match="limit of 2 upstream sessions"):
            await upstreams.for_session("s3", "charlie")
        assert upstreams.started == 2


async def test_an_ended_session_gives_its_place_back() -> None:
    async with sessions(max_total=1, max_per_caller=1) as upstreams:
        await upstreams.for_session("s1", "alpha")
        upstreams.end("s1")
        for _ in range(50):  # the place comes back once its upstream has stopped, in its own task
            with contextlib.suppress(MCPError):
                await upstreams.for_session("s2", "alpha")
                break
            await anyio.sleep(0.01)
        assert upstreams.started == 2


async def test_a_session_already_running_is_not_counted_again() -> None:
    async with sessions(max_total=1, max_per_caller=1) as upstreams:
        for _ in range(3):
            await upstreams.for_session("s1", "alpha")
        assert upstreams.started == 1


async def test_the_agent_is_told_why_its_session_was_refused(tmp_path: Path) -> None:
    data = per_session_config(tmp_path).model_dump(mode="json")
    data["upstream_sessions"] = {"max_per_caller": 1}
    counter = Counter()
    async with running_gateway(GatewayConfig.model_validate(data), counter.connect()) as base:
        url = f"{base}/mcp/fake/"
        async with legacy_agent(url) as first, legacy_agent(url) as second:
            assert not (await first.session.call_tool("read", {})).is_error
            with pytest.raises(MCPError, match="upstream sessions open, its limit"):
                await second.session.call_tool("read", {})
    assert counter.opened == 2  # the start-up probe and the first session only


# --- how long an answer may take ----------------------------------------------


def limits_config(tmp_path: Path, upstream: dict[str, Any]) -> GatewayConfig:
    data = make_config(tmp_path).model_dump(mode="json")
    data["upstreams"] = {"limits": upstream}
    tools = {"slow": {}, "big": {}}
    data["policies"] = {"reader": {"routes": {"limits": {"tools": tools}}}, "echo-only": {"routes": {}}}
    return GatewayConfig.model_validate(data)


async def call_through_gateway(config: GatewayConfig, tool: str, size: int = 10) -> Any:
    """The tool's result, or the error the agent got instead."""
    async with running_gateway(config, connect_upstream) as base, legacy_agent(f"{base}/mcp/limits/") as client:
        with anyio.fail_after(15):  # a missing limit would hang here instead
            try:
                return await client.session.call_tool(tool, {"size": size})
            except MCPError as exc:
                return exc


async def test_a_stdio_upstream_that_never_answers_times_out(tmp_path: Path) -> None:
    upstream = {"transport": "stdio", "command": sys.executable, "args": [str(LIMITS_SERVER)], "read_timeout_s": 0.5}
    error = await call_through_gateway(limits_config(tmp_path, upstream), "slow")
    assert isinstance(error, MCPError) and "timed out" in str(error)


# --- how large an HTTP answer may be --------------------------------------------


@contextlib.asynccontextmanager
async def http_limits_upstream() -> AsyncIterator[str]:
    app = build().streamable_http_app(streamable_http_path="/mcp")
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        await task


async def test_an_http_answer_past_the_byte_cap_is_refused(tmp_path: Path) -> None:
    async with http_limits_upstream() as url:
        config = limits_config(tmp_path, {"transport": "http", "url": url, "max_response_bytes": 50_000})
        error = await call_through_gateway(config, "big", size=200_000)
    assert isinstance(error, MCPError) and "passed 50000 bytes" in str(error)


async def test_an_http_answer_under_the_byte_cap_arrives(tmp_path: Path) -> None:
    async with http_limits_upstream() as url:
        config = limits_config(tmp_path, {"transport": "http", "url": url, "max_response_bytes": 50_000})
        result = await call_through_gateway(config, "big", size=1_000)
    assert not result.is_error and result.content[0].text == "a" * 1_000


async def test_listings_have_their_own_rate_limit(tmp_path: Path) -> None:
    data = make_config(tmp_path).model_dump(mode="json")
    data["callers"]["alpha"]["rate_limit"] = "2/minute"
    async with (
        running_gateway(GatewayConfig.model_validate(data), in_memory(FakeUpstream())) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as alpha,
        agent(f"{base}/mcp/fake/", KEY_B) as bravo,
    ):
        await alpha.session.list_tools()
        await alpha.session.list_tools()
        with pytest.raises(MCPError, match="listing limit \\(2 per 1 minute\\) is used up"):
            await alpha.session.list_tools()
        assert not (await alpha.session.call_tool("echo", {"text": "calls are counted apart"})).is_error
        for _ in range(3):
            await bravo.session.list_tools()  # unlimited key


async def test_the_route_still_works_after_an_answer_past_the_byte_cap(tmp_path: Path) -> None:
    """The cut-off answer fails its one request, not the shared client."""
    async with http_limits_upstream() as url:
        config = limits_config(tmp_path, {"transport": "http", "url": url, "max_response_bytes": 50_000})
        async with running_gateway(config, connect_upstream) as base, legacy_agent(f"{base}/mcp/limits/") as client:
            with contextlib.suppress(MCPError):
                await client.session.call_tool("big", {"size": 200_000})
            after = await client.session.call_tool("big", {"size": 10})
    assert not after.is_error and after.content == [TextContent(type="text", text="a" * 10)]


async def test_the_byte_cap_asks_for_answers_uncompressed() -> None:
    """The cap counts bytes as sent; a compressed body could expand past it."""
    asked_for: list[str | None] = []

    def answer(request: httpx2.Request) -> httpx2.Response:
        asked_for.append(request.headers.get("Accept-Encoding"))
        return httpx2.Response(200, content=b"ok")

    async with httpx2.AsyncClient(transport=CappedTransport(httpx2.MockTransport(answer), 10)) as http:
        await http.get("http://upstream.test/")
    assert asked_for == ["identity"]
