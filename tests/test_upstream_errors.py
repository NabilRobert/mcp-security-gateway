"""An upstream's protocol error is untrusted text too: it reaches the agent
only if the detector passes it, and the audit log never holds it raw."""

import contextlib
import hashlib
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from conftest import KEY_A, agent, make_config, running_gateway
from mcp import Client
from mcp.server import Server
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, ListToolsResult, Tool
from mcp_types.jsonrpc import INVALID_PARAMS
from test_detection import INJECTION, Exploding

from mcp_gateway.config import GatewayConfig
from mcp_gateway.proxy import UPSTREAM_ERROR

pytestmark = pytest.mark.anyio

CLEAN_MESSAGE = "unknown table: rentals"
WITHHELD = "its error message was withheld"


def failing_upstream(message: str, data: Any = None, *, on_list: bool = False) -> Server:
    async def list_tools(ctx: Any, params: Any) -> ListToolsResult:  # noqa: ARG001
        if on_list:
            raise MCPError(INVALID_PARAMS, message, data)
        return ListToolsResult(tools=[Tool(name="lookup", description="ok", input_schema={"type": "object"})])

    async def call_tool(ctx: Any, params: Any) -> CallToolResult:  # noqa: ARG001
        raise MCPError(INVALID_PARAMS, message, data)

    return Server("failing", on_list_tools=list_tools, on_call_tool=call_tool)


def config(tmp_path: Path) -> GatewayConfig:
    policies = {"reader": {"routes": {"fake": {"tools": {"lookup": {}}}}}, "echo-only": {"routes": {}}}
    data = make_config(tmp_path, policies=policies).model_dump(mode="json")
    data["detector"] = {"rules": True}
    return GatewayConfig.model_validate(data)


def connect_to(server: Server) -> Any:
    @contextlib.asynccontextmanager
    async def connect(name: str, upstream: Any) -> AsyncIterator[Client]:  # noqa: ARG001
        async with Client(server) as client:
            yield client

    return connect


def audit(cfg: GatewayConfig) -> str:
    return cfg.audit.path.read_text()


async def error_from_call(cfg: GatewayConfig, server: Server, detector: Any = None) -> MCPError:
    async with (
        running_gateway(cfg, connect_to(server), detector=detector) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as client,
    ):
        with pytest.raises(MCPError) as raised:
            await client.session.call_tool("lookup", {})
    return raised.value


async def test_a_clean_upstream_error_reaches_the_agent_unchanged(tmp_path: Path) -> None:
    error = await error_from_call(config(tmp_path), failing_upstream(CLEAN_MESSAGE))
    assert (error.error.code, error.error.message) == (INVALID_PARAMS, CLEAN_MESSAGE)


async def test_a_flagged_upstream_error_is_withheld_from_the_agent(tmp_path: Path) -> None:
    error = await error_from_call(config(tmp_path), failing_upstream(INJECTION))
    assert error.error.code == UPSTREAM_ERROR
    assert WITHHELD in error.error.message and INJECTION not in error.error.message


async def test_a_flagged_error_data_field_is_withheld_too(tmp_path: Path) -> None:
    error = await error_from_call(config(tmp_path), failing_upstream(CLEAN_MESSAGE, {"hint": INJECTION}))
    assert WITHHELD in error.error.message and error.error.data is None


async def test_a_flagged_key_in_error_data_is_withheld_too(tmp_path: Path) -> None:
    error = await error_from_call(config(tmp_path), failing_upstream(CLEAN_MESSAGE, {INJECTION: 1}))
    assert WITHHELD in error.error.message


async def test_an_upstream_error_is_withheld_when_the_detector_fails(tmp_path: Path) -> None:
    data = config(tmp_path).model_dump(mode="json")
    data["detector"]["scan_tool_descriptions"] = False  # else the tool is hidden before the call
    cfg = GatewayConfig.model_validate(data)
    error = await error_from_call(cfg, failing_upstream(CLEAN_MESSAGE), detector=Exploding())
    assert WITHHELD in error.error.message


async def test_an_oversized_upstream_error_is_withheld(tmp_path: Path) -> None:
    data = config(tmp_path).model_dump(mode="json")
    data["detector"]["scan_cap_chars"] = 10
    error = await error_from_call(GatewayConfig.model_validate(data), failing_upstream(CLEAN_MESSAGE))
    assert WITHHELD in error.error.message


async def test_the_audit_log_records_a_hash_of_the_error_not_its_text(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    await error_from_call(cfg, failing_upstream(INJECTION))
    assert INJECTION not in audit(cfg)
    lines = [json.loads(line) for line in audit(cfg).splitlines()]
    [result] = [line for line in lines if line["kind"] == "result"]
    assert result["decision"] == "upstream_error" and result["error_withheld"] is True
    assert result["error_sha256"] == hashlib.sha256(INJECTION.encode()).hexdigest()
    assert result["error_code"] == INVALID_PARAMS


class ListsOnceThenFails:
    """Serves the start-up listing, then fails every later one."""

    def __init__(self, message: str) -> None:
        self.message = message
        self.listings = 0

    def server(self) -> Server:
        async def list_tools(ctx: Any, params: Any) -> ListToolsResult:  # noqa: ARG001
            self.listings += 1
            if self.listings > 1:
                raise MCPError(INVALID_PARAMS, self.message)
            return ListToolsResult(tools=[Tool(name="lookup", input_schema={"type": "object"})])

        return Server("lists-once", on_list_tools=list_tools)


@pytest.mark.parametrize("step", ["list", "call"])
async def test_an_error_from_a_later_listing_is_screened_too(tmp_path: Path, step: str) -> None:
    """A direct call lists tools to screen the one it's calling."""
    cfg = config(tmp_path)
    async with (
        running_gateway(cfg, connect_to(ListsOnceThenFails(INJECTION).server())) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as client,
    ):
        with pytest.raises(MCPError) as raised:
            if step == "list":
                await client.session.list_tools()
            else:
                await client.session.call_tool("lookup", {})
    assert WITHHELD in raised.value.error.message
    assert INJECTION not in audit(cfg)
