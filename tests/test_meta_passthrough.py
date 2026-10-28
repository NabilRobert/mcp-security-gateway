"""A request's `_meta` reaches the upstream unchanged, with the caller the
gateway authenticated stamped into it (Juku's delegation tokens, spike 6;
W3C trace context). The gateway never logs what `_meta` holds."""

import asyncio
import contextlib
import json
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Literal

import httpx2
import pytest
import uvicorn
from conftest import KEY_A, free_port, make_config, running_gateway
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from meta_echo_server import TOOL, build

from mcp_gateway.app import connect_upstream
from mcp_gateway.config import GatewayConfig

pytestmark = pytest.mark.anyio

# The wire contract with upstreams such as Juku's MCP server: pinned here, not
# imported, so renaming the constant can't silently change the key.
CALLER_KEY = "io.github.nabilrobert.mcp-gateway/caller"
PROTOCOL_PREFIX = "io.modelcontextprotocol/"

DELEGATION_TOKEN = "eyJhbGciOiJFZERTQSJ9.test-delegation-token-must-not-be-logged.c2lnbmF0dXJl"  # noqa: S105 (a test value)
CLIENT_META: dict[str, Any] = {
    "io.github.nabilrobert.juku/delegation": DELEGATION_TOKEN,
    "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    "tracestate": "juku=t61rcWkgMzE",
    "example.com/nested": {"label": "ünïcode ✓", "values": [1, 2.5, None, True], "empty": {}},
}

STDIO_SERVER = Path(__file__).with_name("meta_echo_server.py")


@contextlib.asynccontextmanager
async def http_echo_upstream() -> AsyncIterator[str]:
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


@contextlib.asynccontextmanager
async def echo_gateway(tmp_path: Path, transport: Literal["stdio", "http"]) -> AsyncIterator[str]:
    """A gateway with one route, `echo`, to a real stdio or HTTP upstream."""
    async with contextlib.AsyncExitStack() as stack:
        if transport == "stdio":
            upstream: dict[str, Any] = {"transport": "stdio", "command": sys.executable, "args": [str(STDIO_SERVER)]}
        else:
            upstream = {"transport": "http", "url": await stack.enter_async_context(http_echo_upstream())}
        data = make_config(tmp_path).model_dump(mode="json")
        data["upstreams"] = {"echo": upstream}
        data["policies"] = {"reader": {"routes": {"echo": {"tools": {TOOL: {}}}}}, "echo-only": {"routes": {}}}
        base = await stack.enter_async_context(running_gateway(GatewayConfig.model_validate(data), connect_upstream))
        yield f"{base}/mcp/echo/"


async def meta_seen_upstream(
    url: str, meta: dict[str, Any] | None, mode: Literal["auto", "legacy"] = "auto"
) -> dict[str, Any]:
    """Calls `show_meta` through the gateway with key A; returns the `_meta`
    the upstream received."""
    async with (
        httpx2.AsyncClient(headers={"Authorization": f"Bearer {KEY_A}"}, timeout=30) as http,
        Client(streamable_http_client(url, http_client=http), mode=mode) as client,
    ):
        result = await client.session.call_tool(TOOL, {}, meta=meta)  # pyright: ignore[reportArgumentType]
    assert not result.is_error, result
    return json.loads(result.content[0].text)  # pyright: ignore[reportAttributeAccessIssue]


def without_protocol_keys(meta: dict[str, Any]) -> dict[str, Any]:
    """The upstream's own SDK adds `io.modelcontextprotocol/*` keys for its hop."""
    return {key: value for key, value in meta.items() if not key.startswith(PROTOCOL_PREFIX)}


@pytest.mark.parametrize("mode", ["auto", "legacy"])
@pytest.mark.parametrize("transport", ["stdio", "http"])
async def test_meta_reaches_the_upstream_unchanged(
    tmp_path: Path, transport: Literal["stdio", "http"], mode: Literal["auto", "legacy"]
) -> None:
    async with echo_gateway(tmp_path, transport) as url:
        seen = without_protocol_keys(await meta_seen_upstream(url, CLIENT_META, mode))
    assert seen.pop(CALLER_KEY) == "alpha"
    # Same keys, same order, same JSON types (2.5 stays a float, None stays null).
    assert json.dumps(seen, ensure_ascii=False) == json.dumps(CLIENT_META, ensure_ascii=False)


async def test_a_client_sent_caller_is_overwritten_by_the_authenticated_one(tmp_path: Path) -> None:
    async with echo_gateway(tmp_path, "stdio") as url:
        seen = await meta_seen_upstream(url, {**CLIENT_META, CALLER_KEY: "bravo"})
    assert seen[CALLER_KEY] == "alpha"


async def test_a_call_without_meta_still_carries_the_caller(tmp_path: Path) -> None:
    async with echo_gateway(tmp_path, "stdio") as url:
        seen = without_protocol_keys(await meta_seen_upstream(url, None))
    assert seen == {CALLER_KEY: "alpha"}


async def test_a_progress_token_stays_on_the_agents_hop(tmp_path: Path) -> None:
    """It names a request on the agent's connection, and a shared upstream
    connection carries many agents' calls, where tokens could clash."""
    async with echo_gateway(tmp_path, "stdio") as url:
        seen = await meta_seen_upstream(url, {**CLIENT_META, "progressToken": 7})
    assert "progressToken" not in seen


async def test_the_audit_log_records_meta_was_sent_but_not_what_it_held(tmp_path: Path) -> None:
    """The second call sends no `_meta` of its own: the protocol keys a
    stateless client's SDK adds to every request don't count."""
    async with echo_gateway(tmp_path, "stdio") as url:
        await meta_seen_upstream(url, {**CLIENT_META, CALLER_KEY: "bravo"})
        await meta_seen_upstream(url, None)
    log = (tmp_path / "audit.jsonl").read_text()
    for value in (DELEGATION_TOKEN, CLIENT_META["traceparent"], CLIENT_META["tracestate"]):
        assert value not in log
    calls = [line for line in map(json.loads, log.splitlines()) if line["kind"] == "call"]
    assert [(c["caller"], c["has_meta"], c["is_caller_claim_overwritten"]) for c in calls] == [
        ("alpha", True, True),
        ("alpha", False, False),
    ]
