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
from opentelemetry import trace

from mcp_gateway.app import serve
from mcp_gateway.auth import key_sha256
from mcp_gateway.config import GatewayConfig, HttpUpstream, StdioUpstream


class SwitchableTracerProvider(trace.TracerProvider):
    """Test-only. The global provider can be set once per process, and the
    MCP SDK caches the tracer it gets, so tests switch tracing on and off
    here instead: off (no-op, as in production without an endpoint) unless
    a test sets `active`."""

    def __init__(self) -> None:
        self.active: trace.TracerProvider | None = None

    def get_tracer(self, *args: Any, **kwargs: Any) -> trace.Tracer:
        return _SwitchTracer(self, args, kwargs)


class _SwitchTracer(trace.Tracer):
    def __init__(self, switch: SwitchableTracerProvider, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        self._switch, self._args, self._kwargs = switch, args, kwargs

    def _tracer(self) -> trace.Tracer:
        active = self._switch.active
        return trace.NoOpTracer() if active is None else active.get_tracer(*self._args, **self._kwargs)

    def start_span(self, *args: Any, **kwargs: Any) -> trace.Span:
        return self._tracer().start_span(*args, **kwargs)

    def start_as_current_span(self, *args: Any, **kwargs: Any) -> Any:
        return self._tracer().start_as_current_span(*args, **kwargs)


TRACING = SwitchableTracerProvider()
trace.set_tracer_provider(TRACING)

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
async def running_gateway(config: GatewayConfig, connect: Any, detector: Any = None) -> AsyncIterator[str]:
    port = free_port()
    holder: list[uvicorn.Server] = []
    task = asyncio.create_task(serve(config, port=port, connect=connect, detector=detector, started=holder.append))
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
