"""The smoke test's client, run on the clients network.

Lists the tools through the gateway, calls one and checks the caller stamp
arrived, then checks the upstream can't be reached without the gateway.
Exits non-zero, with the reason, on any failure.
"""

import asyncio
import json
import os
import socket
import sys

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

GATEWAY_URL = "http://mcp-gateway:8000/mcp/echo/"
UPSTREAM_HOST = "echo-mcp"
CALLER_META_KEY = "io.github.nabilrobert.mcp-gateway/caller"
SMOKE_CALLER = "smoke"


async def check_through_gateway(key: str) -> None:
    async with (
        httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=30) as http,
        Client(streamable_http_client(GATEWAY_URL, http_client=http)) as client,
    ):
        tools = [tool.name for tool in (await client.list_tools()).tools]
        if tools != ["show_meta"]:
            sys.exit(f"expected the tool list ['show_meta'], got {tools}")
        result = await client.session.call_tool("show_meta", {}, meta={"example.com/probe": "kept"})  # pyright: ignore[reportArgumentType]
    received = json.loads(result.content[0].text)  # pyright: ignore[reportAttributeAccessIssue]
    if received.get(CALLER_META_KEY) != SMOKE_CALLER or received.get("example.com/probe") != "kept":
        sys.exit(f"the upstream didn't get the caller stamp and the client's _meta: {received}")
    print(f"ok: listed {tools} through the gateway; the upstream got the caller stamp")


def check_upstream_unreachable() -> None:
    try:
        socket.getaddrinfo(UPSTREAM_HOST, 8000)
    except socket.gaierror:
        print(f"ok: {UPSTREAM_HOST} can't be reached from the clients network")
        return
    sys.exit(f"{UPSTREAM_HOST} resolves from the clients network: the gateway can be bypassed")


if __name__ == "__main__":
    asyncio.run(check_through_gateway(os.environ["SMOKE_KEY"]))
    check_upstream_unreachable()
