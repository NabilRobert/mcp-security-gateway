"""A test upstream that answers `show_meta` with the request's `_meta`,
exactly as it arrived, as JSON text.

The `_meta` tests serve it over stdio (run this file) and over HTTP (import
`build`), so each real transport is checked, not only the in-memory one.
"""

import json
from typing import Any

import anyio
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams, TextContent, Tool

TOOL = "show_meta"


async def _list_tools(ctx: ServerRequestContext[Any, Any], params: PaginatedRequestParams | None) -> ListToolsResult:  # noqa: ARG001
    return ListToolsResult(tools=[Tool(name=TOOL, input_schema={"type": "object", "properties": {}})])


async def _call_tool(ctx: ServerRequestContext[Any, Any], params: CallToolRequestParams) -> CallToolResult:  # noqa: ARG001
    # As it was on the wire: the SDK renames `progressToken` in `params.meta`.
    wire_meta = params.model_dump(mode="json", by_alias=True).get("_meta") or {}
    received = json.dumps(wire_meta, ensure_ascii=False)
    return CallToolResult(content=[TextContent(type="text", text=received)])


def build() -> Server:
    return Server("meta-echo", on_list_tools=_list_tools, on_call_tool=_call_tool)


async def _serve_stdio() -> None:
    server = build()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(_serve_stdio)
