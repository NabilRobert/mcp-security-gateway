"""The Host header check (the MCP SDK's DNS-rebinding protection): localhost
only by default, and the names in `allowed_hosts`, such as the gateway's
service name in a container."""

from pathlib import Path

import httpx2
import pytest
from conftest import KEY_A, FakeUpstream, in_memory, make_config, running_gateway

pytestmark = pytest.mark.anyio

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
}
SERVICE_HOST = "mcp-gateway:8000"
MISDIRECTED = 421


async def initialize_status(allowed_hosts: list[str] | None, tmp_path: Path, host: str) -> int:
    config = make_config(tmp_path)
    if allowed_hosts is not None:
        config = config.model_copy(update={"allowed_hosts": allowed_hosts})
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {KEY_A}",
        "Host": host,
    }
    async with running_gateway(config, in_memory(FakeUpstream())) as base, httpx2.AsyncClient() as http:
        response = await http.post(f"{base}/mcp/fake/", headers=headers, json=INITIALIZE)
    return response.status_code


async def test_a_service_name_is_refused_by_default(tmp_path: Path) -> None:
    assert await initialize_status(None, tmp_path, SERVICE_HOST) == MISDIRECTED


async def test_localhost_is_accepted_by_default(tmp_path: Path) -> None:
    assert await initialize_status(None, tmp_path, "127.0.0.1:8000") == httpx2.codes.OK


async def test_a_listed_service_name_is_accepted(tmp_path: Path) -> None:
    assert await initialize_status(["mcp-gateway:*"], tmp_path, SERVICE_HOST) == httpx2.codes.OK


async def test_listing_a_name_replaces_the_localhost_default(tmp_path: Path) -> None:
    assert await initialize_status(["mcp-gateway:*"], tmp_path, "localhost:8000") == MISDIRECTED
