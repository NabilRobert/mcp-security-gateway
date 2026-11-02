"""Tool definitions are scanned like outputs (ADR-011): a tool whose
description looks like an injection is hidden, and calls to it refused."""

import contextlib
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, cast

import pytest
from conftest import KEY_A, agent, in_memory, make_config, running_gateway
from mcp import Client
from mcp.server import MCPServer, Server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool, ToolAnnotations
from pydantic import Field
from test_detection import INJECTION

from mcp_gateway.audit import AuditLog
from mcp_gateway.config import GatewayConfig
from mcp_gateway.detect import DetectorVerdict, RulesDetector
from mcp_gateway.proxy import Route, tool_text
from mcp_gateway.upstreams import list_all_tools

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
    assert refused.is_error and "hidden" in text(refused)
    assert not allowed.is_error
    assert upstream.calls == ["safe"]
    denied = [line for line in audit(cfg) if line.get("decision") == "denied"]
    assert [line["tool"] for line in denied] == ["poisoned"]


def paged_upstream(calls: list[str], pages: dict[str | None, tuple[list[Tool], str | None]]) -> Server:
    async def list_tools(ctx: Any, params: Any) -> ListToolsResult:  # noqa: ARG001
        tools, next_cursor = pages[params.cursor if params else None]
        return ListToolsResult(tools=tools, next_cursor=next_cursor)

    async def call_tool(ctx: Any, params: Any) -> CallToolResult:  # noqa: ARG001
        calls.append(params.name)
        return CallToolResult(content=[TextContent(type="text", text="ran")])

    return Server("paged", on_list_tools=list_tools, on_call_tool=call_tool)


def connect_to(server: Server) -> Any:
    @contextlib.asynccontextmanager
    async def connect(name: str, upstream: Any) -> AsyncIterator[Client]:  # noqa: ARG001
        async with Client(server) as client:
            yield client

    return connect


def plain_tool(name: str, description: str = "A normal tool.") -> Tool:
    return Tool(name=name, description=description, input_schema={"type": "object", "properties": {}})


async def test_a_call_is_screened_against_every_page_of_tools(tmp_path: Path) -> None:
    calls: list[str] = []
    first_page = [plain_tool("safe"), plain_tool("poisoned_param")]
    pages = {None: (first_page, "2"), "2": ([plain_tool("poisoned", INJECTION)], None)}
    cfg = config(tmp_path)
    async with (
        running_gateway(cfg, connect_to(paged_upstream(calls, pages))) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as client,
    ):
        refused = await client.session.call_tool("poisoned", {})
    assert refused.is_error and calls == []


async def test_a_clean_tool_on_a_later_page_still_works(tmp_path: Path) -> None:
    calls: list[str] = []
    first_page = [plain_tool("poisoned"), plain_tool("poisoned_param")]
    pages = {None: (first_page, "2"), "2": ([plain_tool("safe")], None)}
    cfg = config(tmp_path)
    async with (
        running_gateway(cfg, connect_to(paged_upstream(calls, pages))) as base,
        agent(f"{base}/mcp/fake/", KEY_A) as client,
    ):
        result = await client.session.call_tool("safe", {})
    assert not result.is_error and calls == ["safe"]


async def test_a_tool_the_upstream_stops_listing_is_refused(tmp_path: Path) -> None:
    """The start-up check saw it; a later listing doesn't, so it can't be screened."""
    calls: list[str] = []
    listings: list[int] = []
    full = [plain_tool("safe"), plain_tool("poisoned"), plain_tool("poisoned_param")]

    async def list_tools(ctx: Any, params: Any) -> ListToolsResult:  # noqa: ARG001
        listings.append(1)
        return ListToolsResult(tools=full if len(listings) == 1 else [plain_tool("safe")])

    async def call_tool(ctx: Any, params: Any) -> CallToolResult:  # noqa: ARG001
        calls.append(params.name)
        return CallToolResult(content=[TextContent(type="text", text="ran")])

    server = Server("shrinks", on_list_tools=list_tools, on_call_tool=call_tool)
    cfg = config(tmp_path)
    async with running_gateway(cfg, connect_to(server)) as base, agent(f"{base}/mcp/fake/", KEY_A) as client:
        refused = await client.session.call_tool("poisoned", {})
    assert refused.is_error and calls == []


async def test_endless_tool_pages_are_an_upstream_failure_not_a_hang() -> None:
    class Endless:
        async def list_tools(self, params: Any = None) -> ListToolsResult:  # noqa: ARG002
            return ListToolsResult(tools=[], next_cursor="again")

    client: Any = type("EndlessClient", (), {"session": Endless()})()
    with pytest.raises(RuntimeError, match="pages"):
        await list_all_tools(client)


@pytest.mark.parametrize(
    "tool",
    [
        Tool(name="t", input_schema={"properties": {"q": {"type": "string", "title": INJECTION}}}),
        Tool(name="t", input_schema={"properties": {"q": {"type": "string", "default": INJECTION}}}),
        Tool(name="t", input_schema={"properties": {"q": {"enum": ["a", INJECTION]}}}),
        Tool(name="t", input_schema={"properties": {"q": {"default": {"type": INJECTION}}}}),
        Tool(name="t", input_schema={"properties": {"q": {"examples": [{"note": INJECTION}]}}}),
        Tool(name="t", input_schema={"properties": {INJECTION: {"type": "string"}}}),
        Tool(name="t", input_schema={}, output_schema={"properties": {"r": {"description": INJECTION}}}),
        Tool(name="t", input_schema={}, annotations=ToolAnnotations(title=INJECTION)),
        Tool(name=INJECTION, input_schema={}),
    ],
    ids=[
        "title",
        "default",
        "enum",
        "default_object",
        "examples",
        "property_name",
        "output_schema",
        "annotation_title",
        "name",
    ],
)
def test_every_text_a_model_reads_in_a_definition_is_screened(tool: Tool) -> None:
    assert INJECTION in tool_text(tool)


async def test_one_name_listed_twice_gets_one_verdict_on_both(tmp_path: Path) -> None:
    r = route(tmp_path, RulesDetector())
    twins = [plain_tool("twin", INJECTION), plain_tool("twin")]
    assert await r._screen_tools(twins) == {"twin"}  # pyright: ignore[reportPrivateUsage]
    assert await r._screen_tools(twins) == {"twin"}  # pyright: ignore[reportPrivateUsage]


def test_schema_keywords_are_not_read_as_text() -> None:
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["limit"],
        "properties": {"limit": {"type": "integer", "format": "int32", "$ref": "#/$defs/n"}},
    }
    assert tool_text(Tool(name="lookup", input_schema=schema)) == "lookup\nlimit"


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
    assert detector.scanned == ["t\nTitle here\nDescription here\na\nb\nParam A\nNested B"]
