import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer

from mcp_gateway.app import serve
from mcp_gateway.auth import key_sha256
from mcp_gateway.config import GatewayConfig, HttpUpstream, StdioUpstream

KEY_A = "test-key-alpha-0123456789abcdefghijklmnop"
KEY_B = "test-key-bravo-0123456789abcdefghijklmnop"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class FakeUpstream:
    """An in-memory MCP server that records every call it receives."""

    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def server(self) -> MCPServer:
        mcp = MCPServer("fake-upstream")
        calls = self.calls

        @mcp.tool()
        def echo(text: str) -> str:
            """Echo the text back."""
            calls.append(("echo", {"text": text}))
            return f"echo: {text}"

        @mcp.tool()
        def read(path: str) -> str:
            """Read a file."""
            calls.append(("read", {"path": path}))
            return f"contents of {path}"

        @mcp.tool()
        def delete_everything() -> str:
            """A tool no policy should allow."""
            calls.append(("delete_everything", {}))
            return "deleted"

        return mcp


def make_config(tmp_path: Path, policies: dict[str, Any] | None = None) -> GatewayConfig:
    return GatewayConfig.model_validate(
        {
            "upstreams": {"fake": {"transport": "stdio", "command": "unused"}},
            "callers": {
                "alpha": {"key_sha256": key_sha256(KEY_A), "policy": "reader"},
                "bravo": {"key_sha256": key_sha256(KEY_B), "policy": "echo-only"},
            },
            "policies": policies
            or {
                "reader": {
                    "routes": {"fake": {"tools": {"echo": {}, "read": {"arguments": {"path": {"prefix": "docs/"}}}}}}
                },
                "echo-only": {"routes": {"fake": {"tools": {"echo": {}}}}},
            },
            "audit": {"path": str(tmp_path / "audit.jsonl"), "fsync": False},
        }
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass
class RunningGateway:
    base: str
    config: GatewayConfig
    upstream: FakeUpstream

    def url(self, route: str = "fake") -> str:
        return f"{self.base}/mcp/{route}/"


def in_memory(fake: FakeUpstream) -> Callable[[str, HttpUpstream | StdioUpstream], Any]:
    @contextlib.asynccontextmanager
    async def connect(name: str, upstream: HttpUpstream | StdioUpstream) -> AsyncIterator[Client]:  # noqa: ARG001
        async with Client(fake.server()) as client:
            yield client

    return connect


@contextlib.asynccontextmanager
async def running_gateway(config: GatewayConfig, connect: Any) -> AsyncIterator[str]:
    port = free_port()
    holder: list[uvicorn.Server] = []
    task = asyncio.create_task(serve(config, port=port, connect=connect, started=holder.append))
    for _ in range(200):
        if holder and holder[0].started:
            break
        if task.done():
            task.result()  # re-raise a start-up error
        await asyncio.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        holder[0].should_exit = True
        await task


@pytest.fixture
async def gateway(tmp_path: Path) -> AsyncIterator[RunningGateway]:
    fake = FakeUpstream()
    config = make_config(tmp_path)
    async with running_gateway(config, in_memory(fake)) as base:
        yield RunningGateway(base, config, fake)


@contextlib.asynccontextmanager
async def agent(url: str, key: str) -> AsyncIterator[Client]:
    async with (
        httpx2.AsyncClient(headers={"Authorization": f"Bearer {key}"}, timeout=30) as http,
        Client(streamable_http_client(url, http_client=http)) as client,
    ):
        yield client
