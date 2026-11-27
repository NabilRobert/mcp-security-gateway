"""A test upstream for the gateway's limits: `slow` answers after 30 s, and
`big` answers with `size` characters. Served over stdio (run this file) or
HTTP (import `build`), like `meta_echo_server.py`.
"""

from typing import Any

import anyio
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams, TextContent, Tool

SLOW_ANSWER_S = 30  # far past any read timeout a test sets


async def _list_tools(ctx: ServerRequestContext[Any, Any], params: PaginatedRequestParams | None) -> ListToolsResult:  # noqa: ARG001
    schema = {"type": "object", "properties": {"size": {"type": "integer"}}}
    return ListToolsResult(tools=[Tool(name="slow", input_schema=schema), Tool(name="big", input_schema=schema)])


async def _call_tool(ctx: ServerRequestContext[Any, Any], params: CallToolRequestParams) -> CallToolResult:  # noqa: ARG001
    if params.name == "slow":
        await anyio.sleep(SLOW_ANSWER_S)
        return CallToolResult(content=[TextContent(type="text", text="too late")])
    size = int((params.arguments or {}).get("size", 10))
    return CallToolResult(content=[TextContent(type="text", text="a" * size)])


def build() -> Server:
    return Server("limits", on_list_tools=_list_tools, on_call_tool=_call_tool)


async def _serve_stdio() -> None:
    server = build()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(_serve_stdio)
