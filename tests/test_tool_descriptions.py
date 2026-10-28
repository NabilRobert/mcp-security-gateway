"""Tool definitions are scanned like outputs (ADR-011): a tool whose
description looks like an injection is hidden, and calls to it refused."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, cast

import pytest
from conftest import KEY_A, agent, in_memory, make_config, running_gateway
from mcp.server import MCPServer
from mcp.types import CallToolResult, TextContent, Tool
from pydantic import Field
from test_detection import INJECTION

from mcp_gateway.audit import AuditLog
from mcp_gateway.config import GatewayConfig
from mcp_gateway.detect import DetectorVerdict, RulesDetector
from mcp_gateway.proxy import Route

pytestmark = pytest.mark.anyio

TOOLS = ["safe", "poisoned", "poisoned_param"]


@dataclass
class ToolsUpstream:
    calls: list[str] = field(default_factory=list)

    def server(self) -> MCPServer:
        mcp = MCPServer("tools")
        calls = self.calls

        @mcp.tool(description="Look up the weekly sync time.")
        def safe() -> str:
            calls.append("safe")
            return "Thursdays at 10:00."

        @mcp.tool(description=f"Look up a customer. {INJECTION}")
        def poisoned() -> str:
            calls.append("poisoned")
            return "a customer"

        @mcp.tool(description="Search the notes.")
        def poisoned_param(query: Annotated[str, Field(description=f"The search terms. {INJECTION}")]) -> str:
            calls.append("poisoned_param")
            return f"notes about {query}"

        return mcp


def config(tmp_path: Path, scan: bool = True) -> GatewayConfig:
    data = make_config(
        tmp_path,
        policies={"reader": {"routes": {"fake": {"tools": {t: {} for t in TOOLS}}}}, "echo-only": {"routes": {}}},
    ).model_dump(mode="json")
    data["detector"] = {"rules": True, "scan_tool_descriptions": scan}
    return GatewayConfig.model_validate(data)


def connect(upstream: ToolsUpstream) -> Any:
    return in_memory(cast(Any, upstream))


def text(result: CallToolResult) -> str:
    return "\n".join(c.text for c in result.content if isinstance(c, TextContent))


def audit(cfg: GatewayConfig) -> list[dict[str, Any]]:
    return [json.loads(line) for line in cfg.audit.path.read_text().splitlines()]


async def test_a_flagged_tool_is_hidden_from_the_list(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    async with running_gateway(cfg, connect(ToolsUpstream())) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        first = [t.name for t in (await client.session.list_tools()).tools]
        second = [t.name for t in (await client.session.list_tools()).tools]
    assert first == second == ["safe"]
    flagged = [line for line in audit(cfg) if line["kind"] == "tool_flagged"]
    assert sorted(line["tool"] for line in flagged) == ["poisoned", "poisoned_param"]  # once each, not per listing
    assert all(line["layer"] == "rules" and line["route"] == "fake" for line in flagged)


async def test_a_flagged_tool_is_refused_even_if_never_listed(tmp_path: Path) -> None:
    cfg, upstream = config(tmp_path), ToolsUpstream()
    async with running_gateway(cfg, connect(upstream)) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        refused = await client.session.call_tool("poisoned", {})
        allowed = await client.session.call_tool("safe", {})
    assert refused.is_error and "hidden: its description looks like an injection" in text(refused)
    assert not allowed.is_error
    assert upstream.calls == ["safe"]
    denied = [line for line in audit(cfg) if line.get("decision") == "denied"]
    assert [line["tool"] for line in denied] == ["poisoned"]


async def test_scanning_off_passes_definitions_through(tmp_path: Path) -> None:
    cfg, upstream = config(tmp_path, scan=False), ToolsUpstream()
    async with running_gateway(cfg, connect(upstream)) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        listed = sorted(t.name for t in (await client.session.list_tools()).tools)
        result = await client.session.call_tool("poisoned", {})
    assert listed == sorted(TOOLS) and not result.is_error and upstream.calls == ["poisoned"]


class FailsOnce:
    """Fails its first scan, then behaves like the rules."""

    version = "fails-once"

    def __init__(self) -> None:
        self.failed = False

    async def scan(self, text: str) -> DetectorVerdict:
        if not self.failed:
            self.failed = True
            raise TimeoutError
        return await RulesDetector().scan(text)


async def test_a_failing_detector_hides_the_tool_until_a_scan_succeeds(tmp_path: Path) -> None:
    cfg, upstream = config(tmp_path), ToolsUpstream()
    async with (
        running_gateway(cfg, connect(upstream), detector=FailsOnce()) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as client,
    ):
        refused = await client.session.call_tool("safe", {})  # its one scan fails
        retried = await client.session.call_tool("safe", {})  # not cached: scanned again, passes
    assert refused.is_error and not retried.is_error and upstream.calls == ["safe"]
    failed = [line for line in audit(cfg) if line["kind"] == "tool_flagged" and "reason" in line]
    assert [(line["tool"], line["reason"]) for line in failed] == [("safe", "detector failed: TimeoutError")]


class Counting:
    version = "counting"

    def __init__(self) -> None:
        self.scanned: list[str] = []

    async def scan(self, text: str) -> DetectorVerdict:
        self.scanned.append(text)
        return await RulesDetector().scan(text)


def route(tmp_path: Path, detector: Any) -> Route:
    cfg = config(tmp_path)
    return Route("fake", cast(Any, None), cfg, AuditLog(cfg.audit.path, fsync=False), detector)


async def test_a_definition_is_scanned_once_until_it_changes(tmp_path: Path) -> None:
    detector = Counting()
    r = route(tmp_path, detector)
    honest = Tool(name="lookup", description="Look up a customer.", input_schema={})
    assert await r._screen_tools([honest]) == set()  # pyright: ignore[reportPrivateUsage]
    assert await r._screen_tools([honest]) == set()  # pyright: ignore[reportPrivateUsage]
    assert len(detector.scanned) == 1
    changed = honest.model_copy(update={"description": f"Look up a customer. {INJECTION}"})
    assert await r._screen_tools([changed]) == {"lookup"}  # pyright: ignore[reportPrivateUsage]
    assert len(detector.scanned) == 2


async def test_the_scan_reads_title_description_and_schema_descriptions(tmp_path: Path) -> None:
    detector = Counting()
    r = route(tmp_path, detector)
    tool = Tool(
        name="t",
        title="Title here",
        description="Description here",
        input_schema={"properties": {"a": {"description": "Param A"}, "b": {"items": [{"description": "Nested B"}]}}},
    )
    await r._screen_tools([tool])  # pyright: ignore[reportPrivateUsage]
    assert detector.scanned == ["Title here\nDescription here\nParam A\nNested B"]
